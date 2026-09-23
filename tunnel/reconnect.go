/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/reconnect"
)

// This file implements runtime endpoint re-resolution, which WireGuard itself
// has no equivalent of. A peer whose Endpoint is a hostname is resolved exactly
// once, while the tunnel is being brought up, and the resulting address is then
// baked into the driver configuration; the session keeps trying that address
// forever. If the far end is on a dynamic public address what changes is the A
// record, not our configuration, so nothing on our side ever notices, and the
// tunnel stays down until somebody touches it by hand.
//
// The watchdog below closes that gap: it keeps asking whether the tunnel is
// actually carrying traffic, and when it is not, it re-resolves the endpoint
// hostname, pushes the address back into the driver and lets the session
// handshake again.
//
// Detection has two modes:
//
//   - With ReconnectProbe set, the watchdog probes that host:port inside the
//     tunnel, over HTTP by default and over TCP when ReconnectMethod says so.
//     That is the direct question "does the tunnel still pass traffic", and it
//     is what the router-side script does.
//   - Without it, the watchdog uses the age of the peer's last handshake. This
//     needs PersistentKeepalive to be set on the peer, because a session that
//     is carrying nothing does not handshake on its own; the watchdog says so
//     in the log instead of reporting a healthy idle tunnel as dead.
//
// The interval, the per-probe timeout and how many failures in a row are needed
// before acting all come from the configuration, and the probe itself lives in
// the reconnect package so that the tunnel service and the user interface
// measure the same thing the same way.
const (
	// reconnectStartupGrace is how long the watchdog waits before trusting its
	// own verdict, so that the first handshake is not mistaken for a dead
	// tunnel.
	reconnectStartupGrace = 30 * time.Second
	// reconnectMinBackoff and reconnectMaxBackoff bound the delay between
	// recovery attempts while the tunnel stays down. The ceiling is deliberately
	// short: the thing being waited for is a DNS record that some resolver has
	// not let go of yet, and the record is normally updated within a few
	// minutes, so retrying every minute means the new address is picked up
	// within a minute of it existing instead of within five. Retrying this
	// often costs nothing while the tunnel is down, which is the only time it
	// happens: the writes are idempotent and the address being re-applied is
	// the one that is already in the configuration.
	reconnectMinBackoff = 15 * time.Second
	reconnectMaxBackoff = 60 * time.Second
	// reconnectHTTPTimeout bounds one DNS-over-HTTPS or webhook request.
	reconnectHTTPTimeout = 5 * time.Second
)

// configMutationLock serialises writes to a live conf.Config. The same config
// is read by the interface watcher from a Windows notification callback, which
// calls ToDriverConfiguration and SetConfiguration on the adapter, so a
// recovered endpoint must not be written underneath that read.
var configMutationLock sync.Mutex

type reconnectPeerState struct {
	publicKey           conf.Key
	endpointHost        string
	hasEndpoint         bool
	persistentKeepalive uint16
	lastHandshake       time.Time
}

// snapshotEndpointHostnames records the endpoint hostname of every peer before
// conf.Config.ResolveEndpoints replaces it with the address it resolved to.
// Without this snapshot the original name is gone after startup and there is
// nothing left to re-resolve.
func snapshotEndpointHostnames(config *conf.Config) map[conf.Key]string {
	hosts := make(map[conf.Key]string, len(config.Peers))
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.Endpoint.IsEmpty() {
			continue
		}
		if _, err := netip.ParseAddr(peer.Endpoint.Host); err == nil {
			// A literal address has nothing to re-resolve.
			continue
		}
		hosts[peer.PublicKey] = peer.Endpoint.Host
	}
	return hosts
}

// readReconnectPeerStates reads the live configuration back out of the driver,
// which is the only place that knows what the session is really doing.
func readReconnectPeerStates(adapter *driver.Adapter) ([]reconnectPeerState, error) {
	interfaze, err := adapter.Configuration()
	if err != nil {
		return nil, err
	}
	states := make([]reconnectPeerState, 0, interfaze.PeerCount)
	var peer *driver.Peer
	for i := uint32(0); i < interfaze.PeerCount; i++ {
		if peer == nil {
			peer = interfaze.FirstPeer()
		} else {
			peer = peer.NextPeer()
		}
		state := reconnectPeerState{publicKey: conf.Key(peer.PublicKey)}
		if peer.Flags&driver.PeerHasEndpoint != 0 {
			state.hasEndpoint = true
			state.endpointHost = peer.Endpoint.Addr().String()
		}
		if peer.Flags&driver.PeerHasPersistentKeepalive != 0 {
			state.persistentKeepalive = peer.PersistentKeepalive
		}
		if peer.LastHandshake != 0 {
			// The driver reports the handshake as a FILETIME.
			state.lastHandshake = time.Unix(0, int64((peer.LastHandshake-116444736000000000)*100))
		}
		states = append(states, state)
	}
	return states, nil
}

type reconnectWatcher struct {
	adapter *driver.Adapter
	config  *conf.Config
	hosts   map[conf.Key]string

	probeTarget string
	method      reconnect.Method
	interval    time.Duration
	timeout     time.Duration
	threshold   int

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	started  bool

	warnedNoKeepalive bool
}

// newReconnectWatcher returns a watchdog for whichever peers of config have a
// hostname endpoint, or nil when there is nothing to watch.
func newReconnectWatcher(adapter *driver.Adapter, config *conf.Config, hosts map[conf.Key]string) *reconnectWatcher {
	if adapter == nil || config == nil || len(hosts) == 0 {
		return nil
	}
	watcher := &reconnectWatcher{
		adapter:     adapter,
		config:      config,
		hosts:       hosts,
		probeTarget: strings.TrimSpace(config.Interface.ReconnectProbe),
		method:      reconnect.ParseMethod(config.Interface.ReconnectMethod),
		interval:    reconnect.Interval(config.Interface.ReconnectInterval),
		timeout:     reconnect.Timeout(config.Interface.ReconnectTimeout),
		threshold:   reconnect.Threshold(config.Interface.ReconnectThreshold),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	// A probe that is allowed to outlast the interval would keep the loop
	// permanently busy, so cap it rather than letting a typo do that.
	if watcher.timeout > watcher.interval {
		log.Printf("Auto-reconnect: probe timeout reduced from %v to the probe interval of %v", watcher.timeout, watcher.interval)
		watcher.timeout = watcher.interval
	}
	return watcher
}

func (rw *reconnectWatcher) Start() {
	names := make([]string, 0, len(rw.hosts))
	for i := range rw.config.Peers {
		if name, ok := rw.hosts[rw.config.Peers[i].PublicKey]; ok {
			names = append(names, name)
		}
	}
	if rw.probeTarget != "" {
		log.Printf("Auto-reconnect: watching %s, probing %s over %s every %v (timeout %v, %d failures in a row before acting)",
			strings.Join(names, ", "), rw.probeTarget, rw.method, rw.interval, rw.timeout, rw.threshold)
	} else {
		log.Printf("Auto-reconnect: watching %s, judging by handshake age every %v (%d failures in a row before acting)",
			strings.Join(names, ", "), rw.interval, rw.threshold)
	}
	rw.started = true
	go rw.run()
}

// Stop is safe to call whether or not Start ever was: the tunnel service calls
// it from a deferred cleanup that also covers paths which return before the
// watchdog is started, and waiting on a goroutine that does not exist would
// hang the service shutdown.
func (rw *reconnectWatcher) Stop() {
	if !rw.started {
		return
	}
	rw.stopOnce.Do(func() {
		close(rw.stop)
	})
	<-rw.done
}

func (rw *reconnectWatcher) run() {
	defer close(rw.done)

	startedAt := time.Now()
	streak := 0
	attempts := 0
	backoff := reconnectMinBackoff
	var lastAttempt time.Time
	var downAt time.Time
	// awaitingOutcome is set after a recovery attempt and cleared on the next
	// check. A re-apply that reports success only means the write went through;
	// whether the tunnel actually came back is decided by that next check, so
	// the backoff grows on that evidence rather than on the write's return
	// value.
	awaitingOutcome := false
	// downNotified marks that the current outage has already been announced, so
	// that a long one sends a single DOWN notification and keeps one start time.
	downNotified := false

	// How long the tunnel has been down, for the same reason the router-side
	// script reports a duration: it is the number you look at afterwards.
	sinceDown := func() string {
		if downAt.IsZero() {
			return "unknown"
		}
		return time.Since(downAt).Round(time.Second).String()
	}

	ticker := time.NewTicker(rw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rw.stop:
			log.Println("Auto-reconnect: stopping watchdog")
			return
		case <-ticker.C:
		}

		if time.Since(startedAt) < reconnectStartupGrace {
			continue
		}

		states, healthy, detail := rw.inspect()
		if healthy {
			if streak >= rw.threshold {
				log.Printf("Auto-reconnect: the tunnel is carrying traffic again after %s down and %d failed checks", sinceDown(), streak)
				postWebhook(rw.config, "RECOVERED", fmt.Sprintf("Fail Count: %d\nDuration: %s\nDetail: %s", streak, sinceDown(), detail))
			}
			streak = 0
			attempts = 0
			backoff = reconnectMinBackoff
			awaitingOutcome = false
			downNotified = false
			downAt = time.Time{}
			continue
		}

		// The tunnel is still down, so an attempt made before this check did not
		// help. Grow the backoff here: this is the only point where that is
		// known, and doing it in recover()'s caller would mean reacting to the
		// write succeeding rather than to the tunnel recovering.
		if awaitingOutcome {
			awaitingOutcome = false
			backoff *= 2
			if backoff > reconnectMaxBackoff {
				backoff = reconnectMaxBackoff
			}
		}

		streak++
		if streak < rw.threshold {
			log.Printf("Auto-reconnect: tunnel looks unhealthy (%d/%d): %s", streak, rw.threshold, detail)
			continue
		}
		if streak == rw.threshold {
			log.Printf("Auto-reconnect: tunnel is down: %s", detail)
			// streak restarts after every attempt, so this branch is reached
			// again and again during one outage. Only the first one is the
			// state change, and only it should set the clock the reported
			// duration is measured from and send a DOWN notification, or a long
			// outage would both restart its own duration and repeat the alert.
			if !downNotified {
				downNotified = true
				downAt = time.Now()
				postWebhook(rw.config, "DOWN", fmt.Sprintf("Fail Count: %d\nDetail: %s\nAction: Re-resolving endpoint and reconnecting", streak, detail))
			}
		}
		if !lastAttempt.IsZero() && time.Since(lastAttempt) < backoff {
			continue
		}
		lastAttempt = time.Now()
		attempts++
		// The same escalation the router-side script uses: a plain re-apply
		// first, and only if that did not bring the tunnel back, tear the peer
		// down and build it again.
		force := attempts > 1

		ok, report := rw.recover(states, force)
		if ok {
			if force {
				log.Printf("Auto-reconnect: endpoint re-applied and the peer rebuilt from scratch, waiting for a handshake")
			} else {
				log.Printf("Auto-reconnect: endpoint re-applied, waiting for a handshake")
			}
			// Report the streak before clearing it, and leave the backoff alone
			// until the next check says whether this attempt worked. streak
			// restarts so the new session gets a full threshold of checks to
			// complete its handshake in.
			awaitingOutcome = true
			postWebhook(rw.config, "RECOVERY ATTEMPTED", fmt.Sprintf("%s\nFail Count: %d\nDuration: %s", report, streak, sinceDown()))
			streak = 0
			continue
		}
		// The lookup or the write itself failed. That is known now rather than at
		// the next check, so back off immediately.
		awaitingOutcome = false
		backoff *= 2
		if backoff > reconnectMaxBackoff {
			backoff = reconnectMaxBackoff
		}
		log.Printf("Auto-reconnect: recovery failed, next attempt in %v: %s", backoff, report)
		postWebhook(rw.config, "FAILED", fmt.Sprintf("Detail: %s\nFail Count: %d\nNext attempt in: %v\nDuration: %s", report, streak, backoff, sinceDown()))
	}
}

// inspect answers whether the tunnel is still doing its job. It returns the
// driver state alongside the verdict so that a recovery can reuse it instead of
// reading the driver twice.
func (rw *reconnectWatcher) inspect() ([]reconnectPeerState, bool, string) {
	states, err := readReconnectPeerStates(rw.adapter)
	if err != nil {
		return nil, false, fmt.Sprintf("cannot read the driver configuration: %v", err)
	}
	probe := rw.probeTarget
	monitored := 0
	for i := range rw.config.Peers {
		peer := &rw.config.Peers[i]
		host, ok := rw.hosts[peer.PublicKey]
		if !ok || len(host) == 0 {
			continue
		}
		monitored++
		var state *reconnectPeerState
		for j := range states {
			if states[j].publicKey == peer.PublicKey {
				state = &states[j]
				break
			}
		}
		if state == nil {
			continue
		}

		if probe != "" {
			result := reconnect.Probe(rw.method, probe, rw.timeout)
			if !result.Healthy() {
				return states, false, fmt.Sprintf("probe %s failed: %v", probe, result.Err)
			}
			continue
		}

		if state.persistentKeepalive == 0 {
			if !rw.warnedNoKeepalive {
				rw.warnedNoKeepalive = true
				log.Printf("Auto-reconnect: cannot judge %s by handshake age because PersistentKeepalive is not set on the peer; set PersistentKeepalive, or set ReconnectProbe, to make the watchdog effective", host)
			}
			continue
		}
		// Not rw.threshold: this one is how stale a handshake may get, which is
		// a different question from how many failed probes are tolerated.
		ageLimit := reconnect.HandshakeThreshold(state.persistentKeepalive)
		if !state.hasHandshake() {
			return states, false, fmt.Sprintf("no handshake with %s has ever completed", host)
		}
		if age := time.Since(state.lastHandshake); age > ageLimit {
			return states, false, fmt.Sprintf("no handshake with %s for %v (threshold %v)", host, age.Round(time.Second), ageLimit)
		}
	}
	if monitored == 0 {
		return states, true, ""
	}
	return states, true, ""
}

func (s *reconnectPeerState) hasHandshake() bool {
	return !s.lastHandshake.IsZero()
}

// recover re-resolves every watched endpoint and pushes the result back into the
// driver. It reports whether the new configuration could be applied at all, not
// whether the tunnel came back: that is decided by the next health check.
//
// With force set, the peers are rebuilt from scratch rather than updated in
// place. That is the equivalent of the force branch in the router-side script,
// which deletes the peer and sets it up again, and it throws away the session
// and its handshake state along the way.
func (rw *reconnectWatcher) recover(states []reconnectPeerState, force bool) (bool, string) {
	var report strings.Builder
	resolved := make(map[conf.Key]string, len(rw.hosts))
	for i := range rw.config.Peers {
		peer := &rw.config.Peers[i]
		host, ok := rw.hosts[peer.PublicKey]
		if !ok || len(host) == 0 {
			continue
		}
		var current string
		for j := range states {
			if states[j].publicKey == peer.PublicKey && states[j].hasEndpoint {
				current = states[j].endpointHost
			}
		}
		address, method, err := resolveEndpointHost(host, current)
		if err != nil {
			if report.Len() > 0 {
				report.WriteByte('\n')
			}
			fmt.Fprintf(&report, "%s: %v", host, err)
			log.Printf("Auto-reconnect: every resolution method failed for %s: %v", host, err)
			continue
		}
		resolved[peer.PublicKey] = address
		if report.Len() > 0 {
			report.WriteByte('\n')
		}
		if address == current {
			fmt.Fprintf(&report, "%s: still %s (via %s), re-applying to force a new handshake", host, address, method)
			log.Printf("Auto-reconnect: %s still resolves to %s (via %s), re-applying the endpoint to force a new handshake", host, address, method)
		} else {
			fmt.Fprintf(&report, "%s: %s -> %s (via %s)", host, describeEndpoint(current), address, method)
			log.Printf("Auto-reconnect: %s moved from %s to %s (via %s), re-applying the endpoint", host, describeEndpoint(current), address, method)
		}
	}
	if len(resolved) == 0 {
		if report.Len() == 0 {
			report.WriteString("nothing to re-resolve")
		}
		return false, report.String()
	}
	if force {
		report.WriteString("\nrebuilt the peer from scratch instead of updating it in place")
		log.Println("Auto-reconnect: rebuilding the peer from scratch")
	}

	configMutationLock.Lock()
	for i := range rw.config.Peers {
		if address, ok := resolved[rw.config.Peers[i].PublicKey]; ok {
			rw.config.Peers[i].Endpoint.Host = address
		}
	}
	interfaze, size := rw.config.ToDriverConfiguration()
	if force {
		// WIREGUARD_INTERFACE_REPLACE_PEERS means "remove all peers before
		// adding new ones". Asking for that in the same call that carries the
		// new configuration means the peer and its session are built again
		// without ever leaving the interface without a peer, which is what a
		// separate remove-then-add pair would do.
		interfaze.Flags |= driver.InterfaceReplacePeers
	}
	err := rw.adapter.SetConfiguration(interfaze, size)
	configMutationLock.Unlock()
	if err != nil {
		return false, fmt.Sprintf("%s\nUnable to apply the new configuration: %v", report.String(), err)
	}
	return true, report.String()
}

func describeEndpoint(host string) string {
	if len(host) == 0 {
		return "(unset)"
	}
	return host
}

// resolveEndpointHost resolves host through the system resolver and then through
// two independent HTTP resolvers, mirroring the fallback chain the router-side
// script uses.
//
// current is the address the tunnel is already using, and it is known to be
// broken: the watchdog only gets this far after the tunnel stopped passing
// traffic. That changes what counts as an answer. The usual reason a dynamic
// address looks stale is that some resolver still holds the old answer in its
// cache, and a cached answer is not an error, it is a successful lookup that
// returns an outdated value. So stopping at the first resolver that succeeds
// would stop at precisely the cache that needs to be bypassed, which is the
// opposite of what the fallbacks are for. Every resolver is asked instead, an
// address other than current is preferred, and because the three keep
// independent caches, whichever expires first is the one that finds the new
// address.
func resolveEndpointHost(host, current string) (address string, method string, err error) {
	if err := conf.FlushResolverCache(); err != nil {
		log.Printf("Auto-reconnect: unable to flush the DNS resolver cache: %v", err)
	}

	resolvers := []struct {
		name   string
		lookup func(string) ([]string, error)
	}{
		{"system resolver", conf.ResolveHostnameCandidates},
		{"DNS over HTTPS", resolveViaDoH},
		{"ip-api.com over plain HTTP", resolveViaIPAPI},
	}

	var staleAddress, staleMethod string
	for _, resolver := range resolvers {
		candidates, lookupErr := resolver.lookup(host)
		if lookupErr != nil {
			log.Printf("Auto-reconnect: the %s lookup failed for %s: %v", resolver.name, host, lookupErr)
			continue
		}
		found := ""
		for _, candidate := range candidates {
			if candidate != current {
				found = candidate
				break
			}
		}
		if found != "" {
			return found, resolver.name, nil
		}
		if len(candidates) > 0 && staleAddress == "" {
			staleAddress, staleMethod = candidates[0], resolver.name
		}
		log.Printf("Auto-reconnect: the %s still returns the address the tunnel is already using, so asking the next resolver", resolver.name)
	}

	if staleAddress != "" {
		// Every resolver agrees on the address that is already in use, so the
		// DNS record has most likely not been updated yet. Hand that address
		// back anyway: re-applying it forces a fresh handshake, which repairs
		// the case where the session and not the address was the problem.
		log.Printf("Auto-reconnect: no resolver has a different address for %s, so the DNS record has probably not been updated yet", host)
		return staleAddress, staleMethod, nil
	}
	return "", "", errors.New("the system resolver, DNS over HTTPS and ip-api.com all failed")
}

// resolveViaDoH asks AliDNS over HTTPS. The request goes to a fixed public
// resolver rather than to whatever the machine has configured, which is the
// point: it is an independent cache, and it is reached over the physical link
// because the tunnel carries only the configured AllowedIPs.
func resolveViaDoH(host string) ([]string, error) {
	client := &http.Client{Timeout: reconnectHTTPTimeout}
	request, err := http.NewRequest(http.MethodGet, "https://dns.alidns.com/resolve?name="+url.QueryEscape(host)+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", response.Status)
	}
	var parsed struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if parsed.Status != 0 {
		return nil, fmt.Errorf("resolver returned status %d", parsed.Status)
	}
	var addresses []string
	for _, answer := range parsed.Answer {
		if answer.Type != 1 {
			continue
		}
		if address, err := netip.ParseAddr(answer.Data); err == nil && address.Is4() {
			addresses = append(addresses, address.String())
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("no A record in the response")
	}
	return addresses, nil
}

// resolveViaIPAPI asks ip-api.com, which resolves the name with its own
// resolver and answers with the address rather than with the name. It is the
// last resort: plain HTTP, and a third cache that is independent of both the
// machine's resolver and AliDNS.
func resolveViaIPAPI(host string) ([]string, error) {
	client := &http.Client{Timeout: reconnectHTTPTimeout}
	response, err := client.Get("http://ip-api.com/line/" + url.PathEscape(host) + "?fields=query")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<12))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", response.Status)
	}
	text := strings.TrimSpace(string(body))
	if address, err := netip.ParseAddr(text); err == nil && address.Is4() {
		return []string{address.String()}, nil
	}
	return nil, fmt.Errorf("unexpected response %q", text)
}

// postWebhook reports a state change to ReconnectWebhook when one is
// configured. Failures are logged and never affect the tunnel.
func postWebhook(config *conf.Config, status, detail string) {
	endpoint := strings.TrimSpace(config.Interface.ReconnectWebhook)
	if endpoint == "" {
		return
	}
	content := fmt.Sprintf("[WG-WIN] STATUS: %s\nTunnel: %s\nTime: %s\n%s",
		status, config.Name, time.Now().Format("2006-01-02 15:04:05"), detail)
	payload, err := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": content},
	})
	if err != nil {
		log.Printf("Auto-reconnect: unable to encode the webhook payload: %v", err)
		return
	}
	client := &http.Client{Timeout: reconnectHTTPTimeout}
	response, err := client.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Auto-reconnect: unable to post to the webhook: %v", err)
		return
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 1<<12))
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		log.Printf("Auto-reconnect: the webhook answered %s", response.Status)
	}
}

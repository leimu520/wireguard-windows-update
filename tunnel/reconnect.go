/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	crand "crypto/rand"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
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
//     is what the reference script does.
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
	// reconnectPortRotateAfter is the attempt number the watchdog starts
	// rotating the listen port from. Rebuilding the peer twice with the same
	// five-tuple has already failed by then, which is the situation where the
	// path itself has wedged on that tuple: a stateful middlebox between here
	// and the endpoint holds a dead mapping for (local address, listen port,
	// remote endpoint) and answers nothing, while the very retry traffic that
	// is trying to fix the tunnel keeps that poisoned mapping alive. A fresh
	// source port creates a fresh mapping, which is what repaired tunnels on
	// the reference deployments of this same feature. The client is the
	// handshake initiator, so the far end roams to whatever port the packets
	// come from and nothing on the server side needs to change.
	reconnectPortRotateAfter = 3
	// reconnectSilenceAfter and reconnectSilenceWindow define the last rung,
	// the Windows translation of what rebooting a machine buys on the path.
	// Port rotation escapes a single dead mapping, but if several fresh ports
	// all fail the same way, something on the path is wedged more broadly
	// (an over-eager connection tracker, a per-host UDP state table). While
	// the client keeps sending handshakes, that state never gets a chance to
	// expire: the retry traffic is exactly what keeps it alive. This rung
	// takes the peers away entirely, so nothing leaves the UDP socket for
	// reconnectSilenceWindow — comfortably longer than the 30 to 120 seconds
	// consumer firewalls and NATs hold UDP state for — and then rebuilds the
	// session on a fresh port. It is what the shutdown-to-boot gap did by
	// accident on the day this feature was designed from a live outage.
	reconnectSilenceAfter   = 6
	reconnectSilenceWindow  = 120 * time.Second
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
	// silenceUntil holds the deadline of the quiet window while one is in
	// progress. Non-zero means the peers have been stripped and the watchdog
	// deliberately sends nothing until the deadline passes.
	var silenceUntil time.Time
	lastSilenceAttempt := 0

	// How long the tunnel has been down, for the same reason the reference
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
			if silenceUntil.IsZero() {
				if streak >= rw.threshold {
					log.Printf("Auto-reconnect: the tunnel is carrying traffic again after %s down and %d failed checks", sinceDown(), streak)
					postWebhook(rw.config, "RECOVERED", fmt.Sprintf("Fail Count: %d\nDuration: %s\nDetail: %s", streak, sinceDown(), detail))
				}
				streak = 0
				attempts = 0
				// lastSilenceAttempt must be reset along with attempts, or the
				// quiet window of a later outage would not open until attempt
				// lastSilenceAttempt + reconnectSilenceAfter of that outage —
				// a threshold that keeps drifting further out with every
				// outage that used the window.
				lastSilenceAttempt = 0
				backoff = reconnectMinBackoff
				awaitingOutcome = false
				downNotified = false
				downAt = time.Time{}
				continue
			}
			// A quiet window is open, which means the driver currently holds
			// no peers at all, so this "healthy" verdict is an artifact of
			// inspecting an empty configuration — there is no handshake age
			// to be stale and no session to carry probe traffic. Treat it as
			// still down and let the window logic below decide when to
			// rebuild; skipping this would reset the recovery bookkeeping and
			// leave the tunnel peerless forever. The window-opening log
			// already explains this, so it is not repeated on every check.
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
		// While a quiet window is open the watchdog deliberately does nothing:
		// no lookups, no writes, no handshake traffic from the driver. The
		// point of the window is that the path's state for the dead tuple
		// expires in the absence of traffic, and every packet sent during it
		// would cancel exactly that expiry.
		if !silenceUntil.IsZero() {
			if time.Now().Before(silenceUntil) {
				continue
			}
			silenceUntil = time.Time{}
			log.Println("Auto-reconnect: the silence window is over, rebuilding the session on a fresh source port")
		}
		if !lastAttempt.IsZero() && time.Since(lastAttempt) < backoff {
			continue
		}
		lastAttempt = time.Now()
		attempts++
		// The escalation the reference script uses, plus two rungs it cannot
		// pull from a shell script: a plain re-apply first, then tear the peer
		// down and build it again, then bind a new source port so the wedged
		// mapping on the path stops being matched at all, and finally go
		// completely quiet for longer than the path holds UDP state — the one
		// thing a reboot does that no recovery from inside a running service
		// could mimic until now.
		force := attempts > 1
		rotatePort := attempts > reconnectPortRotateAfter

		// Enough rotations have failed that the path is wedged beyond a single
		// dead tuple. Strip the peers, let the path forget everything, and
		// rebuild on the next attempt after the window.
		if silenceUntil.IsZero() && silenceDue(attempts, lastSilenceAttempt) {
			// The attempt budget is spent whether or not the strip lands: if
			// the driver refuses the zero-peer write, retrying it on every
			// attempt would turn the escalation into a strip loop instead of
			// the ordinary attempt that follows.
			lastSilenceAttempt = attempts
			okStrip, stripReport := rw.recover(states, false, false, true)
			if okStrip {
				silenceUntil = time.Now().Add(reconnectSilenceWindow)
				log.Printf("Auto-reconnect: %d consecutive attempts with rotated ports did not help; going quiet for %v so the path's UDP state expires, then rebuilding", attempts-1, reconnectSilenceWindow)
				resyncSystemClock()
				// Report the streak before clearing it. During the window the
				// health checks keep failing (there is no peer to pass traffic
				// through), which is expected and harmless: nothing is sent.
				awaitingOutcome = true
				postWebhook(rw.config, "RECOVERY ATTEMPTED", fmt.Sprintf("%s\nGoing quiet for %v to expire the path's UDP state\nFail Count: %d\nDuration: %s", stripReport, reconnectSilenceWindow, streak, sinceDown()))
				streak = 0
				continue
			}
			// Stripping the peers failed, which is itself diagnostic: fall
			// through to an ordinary attempt and try the quiet window again
			// after another full round of rotations.
			log.Printf("Auto-reconnect: unable to strip the peers for the silence window, continuing with ordinary attempts: %s", stripReport)
		}

		ok, report := rw.recover(states, force, rotatePort, false)
		if ok {
			if rotatePort {
				log.Printf("Auto-reconnect: endpoint re-applied on a new source port, waiting for a handshake")
			} else if force {
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
				// A fresh handshake changes the meaning of the failure: the
				// tunnel itself is up, so endpoint surgery on our side has
				// nothing to fix. Name that in the detail so the log and the
				// webhook point at the probe target or the far end instead of
				// inviting another round of endpoint recovery.
				if state.hasHandshake() && time.Since(state.lastHandshake) < reconnect.HandshakeThreshold(state.persistentKeepalive) {
					return states, false, fmt.Sprintf("probe %s failed: %v (the handshake with %s is fresh, so the tunnel itself is up and the failure is beyond it)", probe, result.Err, host)
				}
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
// place. That is the equivalent of the force branch in the reference script,
// which deletes the peer and sets it up again, and it throws away the session
// and its handshake state along the way.
//
// With rotatePort set, the listen port is rebound to a fresh random value in
// the same call. Everything else about the configuration stays put, so from
// the driver's point of view this is just another configuration write; from
// the path's point of view it is a different five-tuple, which is the only
// thing that helps when a middlebox holds a dead mapping for the old one.
// The rotation applies to the runtime configuration only: the stored
// configuration keeps its original port, so a manual deactivate/activate or a
// reboot puts it back.
//
// With strip set, the peers are removed and nothing is re-added: the driver
// stops sending on the UDP socket entirely, so every stateful device on the
// path can finally age out whatever it holds for the old tuple. The caller
// waits reconnectSilenceWindow before calling again, and the next ordinary
// call rebuilds the peers. Endpoint resolution is skipped on this rung —
// there is nothing to send the answer to — so the report is short by design.
// The stored configuration is never touched by any of these rungs.
func (rw *reconnectWatcher) recover(states []reconnectPeerState, force, rotatePort, strip bool) (bool, string) {
	var report strings.Builder
	if strip {
		configMutationLock.Lock()
		// REPLACE_PEERS with a zero peer count is "remove everything, add
		// nothing": the buffer still carries the peer blobs ToDriverConfiguration
		// wrote, but the driver reads exactly PeerCount of them, which is none.
		interfaze, size := rw.config.ToDriverConfiguration()
		interfaze.Flags |= driver.InterfaceReplacePeers
		interfaze.PeerCount = 0
		err := rw.adapter.SetConfiguration(interfaze, size)
		configMutationLock.Unlock()
		if err != nil {
			return false, "unable to remove the peers for the silence window: " + err.Error()
		}
		log.Println("Auto-reconnect: peers removed, the UDP socket goes quiet so the path's state can expire")
		return true, "peers removed so every stateful device on the path ages out its UDP state"
	}
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
	var newPort uint16
	if rotatePort {
		port, err := randomListenPort(rw.config.Interface.ListenPort)
		if err != nil {
			report.WriteString("\nlisten port rotation skipped: " + err.Error())
			log.Printf("Auto-reconnect: unable to pick a new listen port: %v", err)
		} else {
			newPort = port
			fmt.Fprintf(&report, "\nlisten port rotated from %d to %d to escape a stale mapping on the path", rw.config.Interface.ListenPort, port)
			log.Printf("Auto-reconnect: rotating the listen port from %d to %d, the path holds a dead mapping for the old one", rw.config.Interface.ListenPort, port)
		}
	}

	configMutationLock.Lock()
	for i := range rw.config.Peers {
		if address, ok := resolved[rw.config.Peers[i].PublicKey]; ok {
			rw.config.Peers[i].Endpoint.Host = address
		}
	}
	if newPort != 0 {
		rw.config.Interface.ListenPort = newPort
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
// two independent HTTP resolvers, mirroring the fallback chain the reference
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

// randomListenPort draws a port for the listen-port rotation. Ports below
// 10240 stay out of the way of well-known services, and the port currently
// bound is excluded because reusing it would re-match the very mapping the
// rotation is trying to escape. The draw is retried rather than remapped so
// that the values stay uniformly distributed over the whole usable range.
func randomListenPort(current uint16) (uint16, error) {
	for i := 0; i < 32; i++ {
		var b [2]byte
		if _, err := crand.Read(b[:]); err != nil {
			return 0, err
		}
		port := uint16(b[0])<<8 | uint16(b[1])
		if port < 10240 || port == current {
			continue
		}
		return port, nil
	}
	return 0, errors.New("no usable port drawn after 32 tries")
}

// silenceDue reports whether attempt number attempts should open the quiet
// window. It fires once reconnectSilenceAfter attempts have passed since the
// last window was attempted — opened or refused, both spend the round — so
// that a driver refusing the zero-peer write is retried after another full
// round of rotations rather than on every attempt.
func silenceDue(attempts, lastSilenceAttempt int) bool {
	return attempts > reconnectSilenceAfter && attempts-lastSilenceAttempt >= reconnectSilenceAfter
}

// resyncSystemClock asks the Windows time service to step the clock. It is
// called when the watchdog reaches the silence rung, because one of the ways
// handshakes can fail silently is a clock that stepped backwards: the peer
// replay window rejects any timestamp older than the greatest one it has seen,
// and no amount of rebuilding on our side helps while the clock is still
// wrong. Removing and re-adding the peer in the force rung clears the stored
// greatest-timestamp, so the pairing of the two rungs covers the backward
// step: resync corrects the clock, the rebuild clears the window. Failure is
// logged and never affects the recovery path — the Windows time service may
// not be running, and the rung is a best effort on a side hypothesis.
func resyncSystemClock() {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// The absolute path is deliberate: this runs as LocalSystem and should
	// not depend on what the service's PATH happens to contain.
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\w32tm.exe`, "/resync")
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		log.Printf("Auto-reconnect: the best-effort time resync failed: %v (%s)", err, text)
		return
	}
	log.Printf("Auto-reconnect: best-effort time resync: %s", text)
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

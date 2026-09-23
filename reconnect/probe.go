/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

// Package reconnect holds the probe that decides whether a tunnel is still
// carrying traffic. The tunnel service runs it to drive automatic reconnects
// and the user interface runs the very same code to display what it measures,
// so the number on screen and the number the service acts on cannot drift
// apart.
package reconnect

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Method string

const (
	MethodHTTP Method = "http"
	MethodTCP  Method = "tcp"
)

// Defaults follow the router-side shell script that this feature replaces: ask
// an address inside the tunnel over HTTP, every five seconds, giving up after
// three, and only do something about it after three failures in a row.
const (
	DefaultMethod    = MethodHTTP
	DefaultInterval  = 5 * time.Second
	DefaultTimeout   = 3 * time.Second
	DefaultThreshold = 3
)

// RejectAfterTime is WireGuard's REJECT_AFTER_TIME. A peer whose last handshake
// is older than this cannot be carrying traffic any more.
const RejectAfterTime = 180 * time.Second

// ParseMethod maps the value of the ReconnectMethod configuration key onto a
// method, defaulting to HTTP when the key is absent or unrecognised.
func ParseMethod(s string) Method {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(MethodTCP):
		return MethodTCP
	case string(MethodHTTP), "":
		return MethodHTTP
	}
	return MethodHTTP
}

func (m Method) String() string {
	return string(m)
}

// Result is one probe attempt.
type Result struct {
	Method  Method
	Target  string
	Latency time.Duration
	Status  int
	Err     error
}

func (r Result) Healthy() bool {
	return r.Err == nil
}

func (r Result) String() string {
	if r.Err != nil {
		return r.Err.Error()
	}
	if r.Method == MethodHTTP {
		return fmt.Sprintf("HTTP %d, %v", r.Status, r.Latency.Round(time.Millisecond))
	}
	return fmt.Sprintf("connected, %v", r.Latency.Round(time.Millisecond))
}

// Probe makes one attempt against target, which is expected to live inside the
// tunnel, and reports how long it took.
func Probe(method Method, target string, timeout time.Duration) Result {
	start := time.Now()
	var (
		status int
		err    error
	)
	switch method {
	case MethodTCP:
		err = probeTCP(target, timeout)
	case MethodHTTP:
		status, err = probeHTTP(target, timeout)
	default:
		err = fmt.Errorf("unknown probe method %q", method)
	}
	return Result{
		Method:  method,
		Target:  target,
		Latency: time.Since(start),
		Status:  status,
		Err:     err,
	}
}

func probeTCP(target string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func probeHTTP(target string, timeout time.Duration) (int, error) {
	address, path := SplitTarget(target)
	// A probe asks whether the target is reachable *now*, so it has to open a
	// connection of its own. Riding on the shared default transport means a
	// pooled connection opened before the tunnel broke keeps answering, and the
	// probe cheerfully reports a dead tunnel as healthy: neither a firewall nor
	// a torn-down tunnel disturbs a connection that is already established.
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// A redirect that cannot be followed still proves the tunnel carried
		// the request, so do not chase it and do not turn it into an error.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + address + path)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 1<<12))
	response.Body.Close()
	// Any answer at all is an answer. An HTTP error status is still a response
	// from the far side, so it counts as the tunnel working; only failing to
	// get a response does not.
	return response.StatusCode, nil
}

// SplitTarget separates an optional /path suffix from the host:port part.
func SplitTarget(target string) (address, path string) {
	if i := strings.IndexByte(target, '/'); i >= 0 {
		return target[:i], target[i:]
	}
	return target, "/"
}

// HandshakeThreshold is how stale a handshake may get before a peer with this
// keepalive setting counts as unreachable. Without a keepalive there is no way
// to tell a tunnel that is down from one that is merely idle, so callers should
// insist on one of the two.
func HandshakeThreshold(keepaliveSeconds uint16) time.Duration {
	threshold := RejectAfterTime
	if window := time.Duration(keepaliveSeconds) * time.Second * 3; window > threshold {
		threshold = window
	}
	return threshold
}

// Interval turns a configured number of seconds into a usable duration,
// falling back to the default rather than to a busy loop.
func Interval(seconds uint16) time.Duration {
	if seconds == 0 {
		return DefaultInterval
	}
	return time.Duration(seconds) * time.Second
}

func Timeout(seconds uint16) time.Duration {
	if seconds == 0 {
		return DefaultTimeout
	}
	return time.Duration(seconds) * time.Second
}

func Threshold(count uint16) int {
	if count == 0 {
		return DefaultThreshold
	}
	return int(count)
}

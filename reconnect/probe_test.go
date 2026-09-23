/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package reconnect

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeHTTPCountsAnyResponseAsUp(t *testing.T) {
	// The shell script this replaces only accepts 200 and 403, which turns a
	// perfectly healthy tunnel behind a 404 into a false alarm. Anything the
	// far side answers with means the tunnel carried the request.
	for _, status := range []int{200, 403, 404, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		result := Probe(MethodHTTP, strings.TrimPrefix(server.URL, "http://"), 2*time.Second)
		server.Close()

		if !result.Healthy() {
			t.Errorf("status %d should count as reachable, got %v", status, result.Err)
			continue
		}
		if result.Status != status {
			t.Errorf("status %d reported as %d", status, result.Status)
		}
		// A round trip through a loopback listener can land inside a single
		// clock tick, so zero is a legitimate reading; a negative one is not.
		if result.Latency < 0 {
			t.Errorf("status %d produced a negative latency", status)
		}
	}
}

// A probe that reuses a pooled connection answers a question about the past.
// This is the bug that made the watchdog keep reporting a healthy tunnel while
// every new connection to the probe target was being refused.
func TestProbeHTTPOpensAFreshConnectionEachTime(t *testing.T) {
	var connections int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&connections, 1)
		}
	}
	server.Start()
	defer server.Close()

	target := strings.TrimPrefix(server.URL, "http://")
	for i := range 3 {
		result := Probe(MethodHTTP, target, 2*time.Second)
		if !result.Healthy() {
			t.Fatalf("probe %d failed: %v", i, result.Err)
		}
	}
	if got := atomic.LoadInt32(&connections); got != 3 {
		t.Errorf("three probes opened %d connections, want 3", got)
	}
}

func TestProbeHTTPPathIsUsed(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer server.Close()

	result := Probe(MethodHTTP, strings.TrimPrefix(server.URL, "http://")+"/healthz", 2*time.Second)
	if !result.Healthy() {
		t.Fatalf("probe failed: %v", result.Err)
	}
	if gotPath != "/healthz" {
		t.Errorf("server saw path %q, want %q", gotPath, "/healthz")
	}
}

func TestProbeHTTPDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/nowhere", http.StatusFound)
	}))
	defer server.Close()

	result := Probe(MethodHTTP, strings.TrimPrefix(server.URL, "http://"), 2*time.Second)
	if !result.Healthy() {
		t.Fatalf("a redirect should count as reachable: %v", result.Err)
	}
	if result.Status != http.StatusFound {
		t.Errorf("status %d, want %d", result.Status, http.StatusFound)
	}
}

func TestProbeTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	defer listener.Close()

	result := Probe(MethodTCP, target, 2*time.Second)
	if !result.Healthy() {
		t.Fatalf("probe against a listening socket failed: %v", result.Err)
	}
	if result.Latency < 0 {
		t.Error("latency should never be negative")
	}
	if !strings.Contains(result.String(), "connected") {
		t.Errorf("unexpected description %q", result.String())
	}

	if result := Probe(MethodTCP, target+"/path", 2*time.Second); result.Healthy() {
		t.Error("a path suffix is not valid for a TCP probe")
	}
}

func TestProbeReportsFailure(t *testing.T) {
	// Bind and immediately release a port so that connecting to it is refused.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	listener.Close()

	start := time.Now()
	result := Probe(MethodTCP, target, 2*time.Second)
	if result.Healthy() {
		t.Fatalf("probe against a closed port succeeded")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("probe ran for %v", elapsed)
	}
	if result.String() == "" {
		t.Error("a failure should still describe itself")
	}
}

func TestProbeHonoursTimeout(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3, which goes nowhere.
	start := time.Now()
	result := Probe(MethodHTTP, "203.0.113.9:80", 300*time.Millisecond)
	if result.Healthy() {
		t.Skip("203.0.113.9 answered, cannot test the timeout here")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("a 300ms timeout took %v", elapsed)
	}
}

func TestSplitTarget(t *testing.T) {
	for _, test := range []struct{ in, address, path string }{
		{"10.122.10.1:80", "10.122.10.1:80", "/"},
		{"10.122.10.1:80/", "10.122.10.1:80", "/"},
		{"10.122.10.1:80/healthz", "10.122.10.1:80", "/healthz"},
		{"example.com:8080/a/b", "example.com:8080", "/a/b"},
	} {
		address, path := SplitTarget(test.in)
		if address != test.address || path != test.path {
			t.Errorf("SplitTarget(%q) = %q, %q; want %q, %q", test.in, address, path, test.address, test.path)
		}
	}
}

func TestParseMethod(t *testing.T) {
	for _, test := range []struct {
		in   string
		want Method
	}{
		{"", MethodHTTP},
		{"http", MethodHTTP},
		{"HTTP", MethodHTTP},
		{"tcp", MethodTCP},
		{" TCP ", MethodTCP},
		{"nonsense", MethodHTTP},
	} {
		if got := ParseMethod(test.in); got != test.want {
			t.Errorf("ParseMethod(%q) = %v, want %v", test.in, got, test.want)
		}
	}
}

func TestHandshakeThreshold(t *testing.T) {
	if got := HandshakeThreshold(0); got != RejectAfterTime {
		t.Errorf("no keepalive should fall back to REJECT_AFTER_TIME, got %v", got)
	}
	if got := HandshakeThreshold(25); got != RejectAfterTime {
		t.Errorf("a 25 second keepalive should stay below REJECT_AFTER_TIME, got %v", got)
	}
	if got := HandshakeThreshold(120); got != 360*time.Second {
		t.Errorf("a 120 second keepalive should widen the threshold to 360s, got %v", got)
	}
}

func TestDurationFallbacks(t *testing.T) {
	if Interval(0) != DefaultInterval || Timeout(0) != DefaultTimeout || Threshold(0) != DefaultThreshold {
		t.Error("zero should mean the default, not a zero value")
	}
	if Interval(30) != 30*time.Second || Timeout(7) != 7*time.Second || Threshold(9) != 9 {
		t.Error("configured values should be used as they are")
	}
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/driver"
)

const reconnectTestInput = `
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.122.20.2/24
AutoReconnect = off
ReconnectMethod = tcp
ReconnectProbe = 10.122.10.1:80
ReconnectInterval = 15
ReconnectTimeout = 2
ReconnectThreshold = 5
ReconnectWebhook = https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=00000000-0000-0000-0000-000000000000

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = wishing9ie.com.cn:51829
PersistentKeepalive = 25
AllowedIPs = 10.122.10.0/24, 192.168.11.0/24
`

// The manager service answers RuntimeConfig requests by combining what the
// driver holds with what is stored on disk, and the driver holds none of the
// reconnect settings: they are client-side policy that only ever lives in the
// configuration file. If they are not carried across explicitly they come out
// empty, and because the configuration view shows the runtime configuration
// while a tunnel is up and the stored one while it is down, the settings would
// appear to be lost simply by starting the tunnel.
func TestFromDriverConfigurationKeepsReconnectSettings(t *testing.T) {
	stored := &Config{
		Name: "HOME",
		Interface: Interface{
			Addresses:          nil,
			AutoReconnectOff:   true,
			ReconnectMethod:    "tcp",
			ReconnectProbe:     "10.122.10.1:80",
			ReconnectInterval:  10,
			ReconnectTimeout:   4,
			ReconnectThreshold: 5,
			ReconnectWebhook:   "https://example.invalid/hook",
		},
	}

	// An empty driver interface stands for "the driver is not reporting
	// anything", which is the state that used to drop the settings.
	runtime := FromDriverConfiguration(&driver.Interface{}, stored)
	got := runtime.Interface

	if got.AutoReconnectOff != stored.Interface.AutoReconnectOff {
		t.Errorf("AutoReconnectOff: got %v, want %v", got.AutoReconnectOff, stored.Interface.AutoReconnectOff)
	}
	if got.ReconnectMethod != stored.Interface.ReconnectMethod {
		t.Errorf("ReconnectMethod: got %q, want %q", got.ReconnectMethod, stored.Interface.ReconnectMethod)
	}
	if got.ReconnectProbe != stored.Interface.ReconnectProbe {
		t.Errorf("ReconnectProbe: got %q, want %q", got.ReconnectProbe, stored.Interface.ReconnectProbe)
	}
	if got.ReconnectInterval != stored.Interface.ReconnectInterval {
		t.Errorf("ReconnectInterval: got %d, want %d", got.ReconnectInterval, stored.Interface.ReconnectInterval)
	}
	if got.ReconnectTimeout != stored.Interface.ReconnectTimeout {
		t.Errorf("ReconnectTimeout: got %d, want %d", got.ReconnectTimeout, stored.Interface.ReconnectTimeout)
	}
	if got.ReconnectThreshold != stored.Interface.ReconnectThreshold {
		t.Errorf("ReconnectThreshold: got %d, want %d", got.ReconnectThreshold, stored.Interface.ReconnectThreshold)
	}
	if got.ReconnectWebhook != stored.Interface.ReconnectWebhook {
		t.Errorf("ReconnectWebhook: got %q, want %q", got.ReconnectWebhook, stored.Interface.ReconnectWebhook)
	}
}

func TestReconnectConfigParsing(t *testing.T) {
	c, err := FromWgQuick(reconnectTestInput, "test")
	if !noError(t, err) {
		return
	}

	equal(t, true, c.Interface.AutoReconnectOff)
	equal(t, "tcp", c.Interface.ReconnectMethod)
	equal(t, "10.122.10.1:80", c.Interface.ReconnectProbe)
	equal(t, uint16(15), c.Interface.ReconnectInterval)
	equal(t, uint16(2), c.Interface.ReconnectTimeout)
	equal(t, uint16(5), c.Interface.ReconnectThreshold)
	equal(t, "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=00000000-0000-0000-0000-000000000000", c.Interface.ReconnectWebhook)

	serialized := c.ToWgQuick()
	for _, want := range []string{
		"AutoReconnect = off\n",
		"ReconnectMethod = tcp\n",
		"ReconnectProbe = 10.122.10.1:80\n",
		"ReconnectInterval = 15\n",
		"ReconnectTimeout = 2\n",
		"ReconnectThreshold = 5\n",
		"ReconnectWebhook = https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=00000000-0000-0000-0000-000000000000\n",
	} {
		if !strings.Contains(serialized, want) {
			t.Errorf("serialized config missing %q in:\n%s", want, serialized)
		}
	}

	reparsed, err := FromWgQuick(serialized, "test")
	if noError(t, err) {
		equal(t, serialized, reparsed.ToWgQuick())
		equal(t, c, reparsed)
	}
}

// A configuration that never mentions the new keys has to come back out
// unchanged, otherwise every existing tunnel would grow a block of lines the
// first time it is opened in the editor.
func TestReconnectConfigDefaultsAreInvisible(t *testing.T) {
	c, err := FromWgQuick(testInput, "test")
	if !noError(t, err) {
		return
	}

	equal(t, false, c.Interface.AutoReconnectOff)
	equal(t, "", c.Interface.ReconnectMethod)
	equal(t, "", c.Interface.ReconnectProbe)
	equal(t, uint16(0), c.Interface.ReconnectInterval)
	equal(t, uint16(0), c.Interface.ReconnectTimeout)
	equal(t, uint16(0), c.Interface.ReconnectThreshold)
	equal(t, "", c.Interface.ReconnectWebhook)

	serialized := c.ToWgQuick()
	for _, unwanted := range []string{"AutoReconnect", "ReconnectMethod", "ReconnectProbe", "ReconnectInterval", "ReconnectTimeout", "ReconnectThreshold", "ReconnectWebhook"} {
		if strings.Contains(serialized, unwanted) {
			t.Errorf("serialized config unexpectedly mentions %q in:\n%s", unwanted, serialized)
		}
	}
}

func TestReconnectConfigRejectsInvalidValues(t *testing.T) {
	for _, key := range []string{
		"AutoReconnect = maybe",
		"AutoReconnect = ",
		"ReconnectMethod = icmp",
		"ReconnectProbe = 10.122.10.1",
		"ReconnectProbe = 10.122.10.1:99999",
		"ReconnectProbe = 10.122.10.1:80/has space",
		"ReconnectInterval = 0",
		"ReconnectInterval = -5",
		"ReconnectInterval = 70000",
		"ReconnectInterval = five",
		"ReconnectTimeout = 0",
		"ReconnectThreshold = 0",
		"ReconnectWebhook = nope",
		"ReconnectWebhook = ftp://example.com/hook",
	} {
		input := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n" + key + "\n"
		if _, err := FromWgQuick(input, "test"); err == nil {
			t.Errorf("expected %q to be rejected", key)
		}
	}
}

func TestReconnectConfigAcceptsOnSpellings(t *testing.T) {
	for _, on := range []string{"on", "true", "yes", "1"} {
		input := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAutoReconnect = " + on + "\n"
		c, err := FromWgQuick(input, "test")
		if !noError(t, err) {
			continue
		}
		if c.Interface.AutoReconnectOff {
			t.Errorf("AutoReconnect = %s should not disable reconnecting", on)
		}
	}
}

func TestReconnectProbeAcceptsPath(t *testing.T) {
	for _, probe := range []string{"10.122.10.1:80", "10.122.10.1:80/", "10.122.10.1:80/healthz", "[fd00::1]:80/api", "example.com:8080/a/b"} {
		input := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nReconnectProbe = " + probe + "\n"
		c, err := FromWgQuick(input, "test")
		if !noError(t, err) {
			continue
		}
		equal(t, probe, c.Interface.ReconnectProbe)
	}
}

func TestReconnectMethodIsCaseInsensitive(t *testing.T) {
	input := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nReconnectMethod = HTTP\n"
	c, err := FromWgQuick(input, "test")
	if !noError(t, err) {
		return
	}
	equal(t, "http", c.Interface.ReconnectMethod)
}

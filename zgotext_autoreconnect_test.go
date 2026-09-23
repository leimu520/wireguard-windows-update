/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"testing"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// The reconnect strings are looked up in the catalog that zgotext.go installs,
// so they are only translated for as long as their keys keep matching the
// format strings the user interface passes in. This checks that they do.
//
// The tag has to be spelled exactly zh-CN: the catalog registers its dictionary
// under that tag from the locales/zh-CN directory name, and neither zh-Hans nor
// zh-Hans-CN resolves to it, even though CLDR considers them related.
func TestAutoReconnectCatalog(t *testing.T) {
	printer := message.NewPrinter(language.MustParse("zh-CN"))

	for _, test := range []struct {
		args []any
		key  string
		want string
	}{
		{key: "&Reconnect status", want: "隧道检测状态 (&R)"},
		{key: "Reconnect &parameters", want: "参数编辑 (&P)"},
		{key: "&Probe now", want: "立即探测 (&P)"},
		{key: "Tunnel:", want: "隧道:"},
		{key: "Automatic reconnect:", want: "自动重连:"},
		{key: "Probe method:", want: "探测方式:"},
		{key: "Probe target:", want: "探测地址:"},
		{key: "Probe interval:", want: "探测间隔:"},
		{key: "Probe timeout:", want: "探测超时:"},
		{key: "Failures tolerated:", want: "容忍失败次数:"},
		{key: "Current endpoint:", want: "当前对端地址:"},
		{key: "Last handshake:", want: "上次握手:"},
		{key: "Traffic:", want: "流量:"},
		{key: "Probe result:", want: "探测结果:"},
		{key: "Latency:", want: "延迟:"},
		{key: "Failures in a row:", want: "连续失败:"},
		{key: "Assessment:", want: "判定:"},
		{key: "Probe &target:", want: "探测地址 (&T):"},
		{key: "Probe &interval (seconds):", want: "探测间隔（秒）(&I):"},
		{key: "Probe &timeout (seconds):", want: "探测超时（秒）(&O):"},
		{key: "Failures &tolerated:", want: "容忍失败次数 (&F):"},
		{key: "&Webhook:", want: "告警地址 (&W):"},
		{key: "Probe &method:", want: "探测方式 (&M):"},
		{key: "&Reconnect automatically if the endpoint address changes", want: "对端地址变化时自动重连 (&R)"},
		{key: "HTTP request (any answer counts)", want: "HTTP 请求（任何响应都算通）"},
		{key: "TCP connection", want: "TCP 连接"},
		{key: "the tunnel is carrying traffic", want: "隧道正在正常传输"},
		{key: "disabled", want: "已停用"},
		{key: "no probe target is configured", want: "未配置探测地址"},
		{key: "(none)", want: "(无)"},
		{key: "never", want: "从未"},
		{args: []any{"HOME"}, key: "Reconnect status – %s", want: "重连检测状态 - HOME"},
		{args: []any{"HOME"}, key: "Reconnect settings – %s", want: "重连参数 - HOME"},
		{args: []any{2, 3}, key: "no answer yet (%d of %d failures)", want: "尚未响应（2/3 次失败）"},
		{args: []any{"8.5 KiB", "3.84 KiB"}, key: "received %s, sent %s", want: "接收 8.5 KiB，发送 3.84 KiB"},
		{key: "Shows what the tunnel check is seeing. The actual checking and reconnecting is done by the tunnel service.",
			want: "显示隧道检测的结果。实际的检测与重连由隧道服务执行。"},
		{args: []any{"18:30:00"}, key: "Shows what the tunnel check is seeing. The actual checking and reconnecting is done by the tunnel service. Last check: %s",
			want: "显示隧道检测的结果。实际的检测与重连由隧道服务执行。最近检查: 18:30:00"},
		{key: "Deactivated", want: "已断开"},
		// The catalog is keyed by the format string as it is written in the
		// source, not by the {Placeholder} form the locale files use.
		{args: []any{"4.5"}, key: "%s must be between 1 and 65535", want: "4.5必须在 1 到 65535 之间"},
		{args: []any{"probe interval"}, key: "Invalid %s", want: "probe interval无效"},
	} {
		got := printer.Sprintf(test.key, test.args...)
		if got != test.want {
			t.Errorf("Sprintf(%q) = %q, want %q", test.key, got, test.want)
		}
	}
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/reconnect"
)

// reconnectSettings is the part of a tunnel's configuration that the watchdog
// runs on, pulled out of conf.Config so that both dialogs below can talk about
// it without repeating the "zero means default" rules.
type reconnectSettings struct {
	enabled   bool
	method    reconnect.Method
	target    string
	interval  time.Duration
	timeout   time.Duration
	threshold int
}

func settingsFromConfig(c *conf.Config) reconnectSettings {
	return reconnectSettings{
		enabled:   !c.Interface.AutoReconnectOff,
		method:    reconnect.ParseMethod(c.Interface.ReconnectMethod),
		target:    strings.TrimSpace(c.Interface.ReconnectProbe),
		interval:  reconnect.Interval(c.Interface.ReconnectInterval),
		timeout:   reconnect.Timeout(c.Interface.ReconnectTimeout),
		threshold: reconnect.Threshold(c.Interface.ReconnectThreshold),
	}
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// reconnectStatusDialog shows what the watchdog would be looking at right now.
// The probe runs here, in the user interface process, rather than being read out
// of the tunnel service, because the two do not talk to each other; the point
// is that both use the very same reconnect package, so the numbers agree.
type reconnectStatusDialog struct {
	*walk.Dialog

	tunnel  *manager.Tunnel
	setting reconnectSettings

	tunnelName *walk.LineEdit
	enabled    *walk.LineEdit
	method     *walk.LineEdit
	target     *walk.LineEdit
	interval   *walk.LineEdit
	timeout    *walk.LineEdit
	threshold  *walk.LineEdit

	endpoint  *walk.LineEdit
	handshake *walk.LineEdit
	traffic   *walk.LineEdit
	verdict   *walk.LineEdit
	result    *walk.LineEdit
	latency   *walk.LineEdit
	failures  *walk.LineEdit

	footer *walk.TextLabel

	stopOnce sync.Once
	stop     chan struct{}

	streak int
}

func runReconnectStatusDialog(owner walk.Form, tunnel *manager.Tunnel) {
	if tunnel == nil {
		return
	}
	dlg, err := newReconnectStatusDialog(owner, tunnel)
	if showError(err, owner) {
		return
	}
	dlg.Run()
}

func (dlg *reconnectStatusDialog) addRow(layout *walk.GridLayout, row int, caption string) (*walk.LineEdit, error) {
	label, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	label.SetTextAlignment(walk.AlignHFarVCenter)
	label.SetText(caption)
	layout.SetRange(label, walk.Rectangle{0, row, 1, 1})

	value, err := walk.NewLineEdit(dlg)
	if err != nil {
		return nil, err
	}
	value.SetReadOnly(true)
	value.SetText(l18n.Sprintf("(unknown)"))
	layout.SetRange(value, walk.Rectangle{1, row, 1, 1})
	return value, nil
}

func newReconnectStatusDialog(owner walk.Form, tunnel *manager.Tunnel) (*reconnectStatusDialog, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg := &reconnectStatusDialog{
		tunnel: tunnel,
		stop:   make(chan struct{}),
	}

	// The stored configuration says what the watchdog is set up to do.
	stored, err := tunnel.StoredConfig()
	if err != nil {
		return nil, err
	}
	dlg.setting = settingsFromConfig(&stored)

	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		return nil, err
	}
	disposables.Add(dlg)
	dlg.SetTitle(l18n.Sprintf("Reconnect status – %s", tunnel.Name))
	dlg.SetIcon(owner.Icon())
	if icon, err := loadSystemIcon("imageres", -114, 32); err == nil {
		dlg.SetIcon(icon)
	}
	layout := walk.NewGridLayout()
	layout.SetSpacing(6)
	layout.SetMargins(walk.Margins{10, 10, 10, 10})
	layout.SetColumnStretchFactor(1, 3)
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{480, 300}, walk.Size{0, 0})

	row := 0
	for _, item := range []struct {
		caption string
		target  **walk.LineEdit
	}{
		{l18n.Sprintf("Tunnel:"), &dlg.tunnelName},
		{l18n.Sprintf("Automatic reconnect:"), &dlg.enabled},
		{l18n.Sprintf("Probe method:"), &dlg.method},
		{l18n.Sprintf("Probe target:"), &dlg.target},
		{l18n.Sprintf("Probe interval:"), &dlg.interval},
		{l18n.Sprintf("Probe timeout:"), &dlg.timeout},
		{l18n.Sprintf("Failures tolerated:"), &dlg.threshold},
		{l18n.Sprintf("Current endpoint:"), &dlg.endpoint},
		{l18n.Sprintf("Last handshake:"), &dlg.handshake},
		{l18n.Sprintf("Traffic:"), &dlg.traffic},
		{l18n.Sprintf("Probe result:"), &dlg.result},
		{l18n.Sprintf("Latency:"), &dlg.latency},
		{l18n.Sprintf("Failures in a row:"), &dlg.failures},
		{l18n.Sprintf("Assessment:"), &dlg.verdict},
	} {
		value, err := dlg.addRow(layout, row, item.caption)
		if err != nil {
			return nil, err
		}
		*item.target = value
		row++
	}

	footer, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(footer, walk.Rectangle{0, row, 2, 1})
	footer.SetText(l18n.Sprintf("Shows what the tunnel check is seeing. The actual checking and reconnecting is done by the tunnel service."))
	dlg.footer = footer
	row++

	buttons, err := walk.NewComposite(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(buttons, walk.Rectangle{0, row, 2, 1})
	buttons.SetLayout(walk.NewHBoxLayout())
	buttons.Layout().SetMargins(walk.Margins{})

	refreshButton, err := walk.NewPushButton(buttons)
	if err != nil {
		return nil, err
	}
	refreshButton.SetText(l18n.Sprintf("&Probe now"))
	refreshButton.Clicked().Attach(dlg.refreshNow)
	walk.NewHSpacer(buttons)
	closeButton, err := walk.NewPushButton(buttons)
	if err != nil {
		return nil, err
	}
	closeButton.SetText(l18n.Sprintf("Close"))
	closeButton.Clicked().Attach(dlg.Cancel)
	dlg.SetCancelButton(closeButton)
	dlg.SetDefaultButton(refreshButton)

	dlg.fillSettings()
	dlg.Starting().Attach(dlg.start)
	dlg.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		dlg.stopOnce.Do(func() { close(dlg.stop) })
	})

	disposables.Spare()
	return dlg, nil
}

func (dlg *reconnectStatusDialog) fillSettings() {
	dlg.tunnelName.SetText(dlg.tunnel.Name)
	if dlg.setting.enabled {
		dlg.enabled.SetText(l18n.Sprintf("enabled"))
	} else {
		dlg.enabled.SetText(l18n.Sprintf("disabled"))
	}
	if dlg.setting.target == "" {
		dlg.method.SetText(l18n.Sprintf("not used, judging by handshake age"))
		dlg.target.SetText(l18n.Sprintf("not configured"))
	} else {
		dlg.method.SetText(dlg.setting.method.String())
		dlg.target.SetText(dlg.setting.target)
	}
	dlg.interval.SetText(fmt.Sprintf("%v", dlg.setting.interval))
	dlg.timeout.SetText(fmt.Sprintf("%v", dlg.setting.timeout))
	dlg.threshold.SetText(strconv.Itoa(dlg.setting.threshold))
}

func (dlg *reconnectStatusDialog) stopped() bool {
	select {
	case <-dlg.stop:
		return true
	default:
		return false
	}
}

func (dlg *reconnectStatusDialog) start() {
	go func() {
		ticker := time.NewTicker(dlg.setting.interval)
		defer ticker.Stop()
		dlg.refreshOnce()
		for {
			select {
			case <-dlg.stop:
				return
			case <-ticker.C:
				dlg.refreshOnce()
			}
		}
	}()
}

func (dlg *reconnectStatusDialog) refreshNow() {
	go dlg.refreshOnce()
}

func (dlg *reconnectStatusDialog) refreshOnce() {
	var result reconnect.Result
	if dlg.setting.target != "" {
		result = reconnect.Probe(dlg.setting.method, dlg.setting.target, dlg.setting.timeout)
	} else {
		result = reconnect.Result{Err: errors.New(l18n.Sprintf("no probe target is configured"))}
	}
	// Reading the live peer state goes through the manager service, which is
	// the only side allowed to open the driver.
	runtime, runtimeErr := dlg.tunnel.RuntimeConfig()
	var peer *conf.Peer
	if runtimeErr == nil && len(runtime.Peers) > 0 {
		peer = &runtime.Peers[0]
	}
	dlg.Synchronize(func() {
		if dlg.stopped() || !dlg.Visible() {
			return
		}
		dlg.apply(result, peer, runtimeErr)
	})
}

func (dlg *reconnectStatusDialog) apply(result reconnect.Result, peer *conf.Peer, runtimeErr error) {
	if dlg.setting.target != "" && !result.Healthy() {
		dlg.streak++
	} else if dlg.setting.target != "" {
		dlg.streak = 0
	}

	if dlg.setting.target == "" {
		dlg.result.SetText(l18n.Sprintf("no probe configured"))
		dlg.latency.SetText("-")
	} else {
		dlg.result.SetText(result.String())
		if result.Healthy() {
			dlg.latency.SetText(fmt.Sprintf("%d ms", result.Latency.Milliseconds()))
		} else {
			dlg.latency.SetText("-")
		}
	}
	dlg.failures.SetText(strconv.Itoa(dlg.streak))

	if runtimeErr != nil {
		dlg.endpoint.SetText(l18n.Sprintf("(unavailable: %v)", runtimeErr))
		dlg.handshake.SetText(l18n.Sprintf("(unavailable)"))
		dlg.traffic.SetText(l18n.Sprintf("(unavailable)"))
		dlg.verdict.SetText(l18n.Sprintf("the tunnel is not running"))
		return
	}
	if peer == nil {
		dlg.endpoint.SetText(l18n.Sprintf("(none)"))
		dlg.handshake.SetText(l18n.Sprintf("(none)"))
		dlg.traffic.SetText(l18n.Sprintf("(none)"))
		dlg.verdict.SetText(l18n.Sprintf("no peer in the running configuration"))
		return
	}
	dlg.endpoint.SetText(peer.Endpoint.String())
	if peer.LastHandshakeTime.IsEmpty() {
		dlg.handshake.SetText(l18n.Sprintf("never"))
	} else {
		dlg.handshake.SetText(peer.LastHandshakeTime.String())
	}
	dlg.traffic.SetText(l18n.Sprintf("received %s, sent %s", peer.RxBytes.String(), peer.TxBytes.String()))
	dlg.verdict.SetText(dlg.assess(result, peer))
	// Keeping the timestamp visible is what makes "it refreshes on its own"
	// something you can check rather than something you have to believe.
	dlg.footer.SetText(l18n.Sprintf("Shows what the tunnel check is seeing. The actual checking and reconnecting is done by the tunnel service. Last check: %s",
		time.Now().Format("15:04:05")))
}

// assess answers the same question the tunnel service asks itself, in the same
// order: probe first when one is configured, otherwise handshake age against
// the same threshold the watchdog uses.
func (dlg *reconnectStatusDialog) assess(result reconnect.Result, peer *conf.Peer) string {
	if dlg.setting.target != "" {
		if result.Healthy() {
			return l18n.Sprintf("the tunnel is carrying traffic")
		}
		if dlg.streak < dlg.setting.threshold {
			return l18n.Sprintf("no answer yet (%d of %d failures)", dlg.streak, dlg.setting.threshold)
		}
		return l18n.Sprintf("the tunnel looks down; the service should be re-resolving the endpoint")
	}
	if peer.PersistentKeepalive == 0 {
		return l18n.Sprintf("cannot be judged: no probe target and no PersistentKeepalive")
	}
	if peer.LastHandshakeTime.IsEmpty() {
		return l18n.Sprintf("no handshake has completed yet")
	}
	threshold := reconnect.HandshakeThreshold(peer.PersistentKeepalive)
	age := time.Duration(peer.LastHandshakeTime)
	if age > threshold {
		return l18n.Sprintf("no handshake for %v, past the %v threshold", age.Round(time.Second), threshold)
	}
	return l18n.Sprintf("the tunnel is carrying traffic")
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

type reconnectSettingsDialog struct {
	*walk.Dialog

	enabled   *walk.CheckBox
	method    *walk.ComboBox
	target    *walk.LineEdit
	interval  *walk.LineEdit
	timeout   *walk.LineEdit
	threshold *walk.LineEdit
	webhook   *walk.LineEdit

	config conf.Config
}

func runReconnectSettingsDialog(owner walk.Form, tunnel *manager.Tunnel) *conf.Config {
	if tunnel == nil {
		return nil
	}
	dlg, err := newReconnectSettingsDialog(owner, tunnel)
	if showError(err, owner) {
		return nil
	}
	if dlg.Run() == walk.DlgCmdOK {
		return &dlg.config
	}
	return nil
}

func newReconnectSettingsDialog(owner walk.Form, tunnel *manager.Tunnel) (*reconnectSettingsDialog, error) {
	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg := new(reconnectSettingsDialog)
	if dlg.config, err = tunnel.StoredConfig(); err != nil {
		return nil, err
	}
	setting := settingsFromConfig(&dlg.config)

	if dlg.Dialog, err = walk.NewDialog(owner); err != nil {
		return nil, err
	}
	disposables.Add(dlg)
	dlg.SetTitle(l18n.Sprintf("Reconnect settings – %s", tunnel.Name))
	dlg.SetIcon(owner.Icon())
	if icon, err := loadSystemIcon("imageres", -114, 32); err == nil {
		dlg.SetIcon(icon)
	}
	layout := walk.NewGridLayout()
	layout.SetSpacing(6)
	layout.SetMargins(walk.Margins{10, 10, 10, 10})
	layout.SetColumnStretchFactor(1, 3)
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{500, 260}, walk.Size{0, 0})

	enabled, err := walk.NewCheckBox(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(enabled, walk.Rectangle{0, 0, 2, 1})
	enabled.SetText(l18n.Sprintf("&Reconnect automatically if the endpoint address changes"))
	enabled.SetToolTipText(l18n.Sprintf("Applies to this tunnel only, and is stored in its configuration as AutoReconnect. The tunnel service reads it, so changing it restarts the tunnel."))
	dlg.enabled = enabled

	row := 1
	for _, item := range []struct {
		caption string
		tooltip string
		target  **walk.LineEdit
	}{
		{l18n.Sprintf("Probe &target:"), l18n.Sprintf("Something inside the tunnel that answers, such as 10.122.10.1:80, optionally with a path for the HTTP method, such as 10.122.10.1:80/healthz. Leave it empty to judge the tunnel by handshake age instead."), &dlg.target},
		{l18n.Sprintf("Probe &interval (seconds):"), l18n.Sprintf("How often the tunnel service probes. Empty means %d.", int(reconnect.DefaultInterval.Seconds())), &dlg.interval},
		{l18n.Sprintf("Probe &timeout (seconds):"), l18n.Sprintf("How long a single probe may take before it counts as a failure. Empty means %d; it is capped at the interval.", int(reconnect.DefaultTimeout.Seconds())), &dlg.timeout},
		{l18n.Sprintf("Failures &tolerated:"), l18n.Sprintf("How many probes in a row may fail before the service re-resolves the endpoint. Empty means %d.", reconnect.DefaultThreshold), &dlg.threshold},
		{l18n.Sprintf("&Webhook:"), l18n.Sprintf("Optional URL that receives a text message whenever the tunnel is declared down, recovers, or fails to recover."), &dlg.webhook},
	} {
		label, err := walk.NewTextLabel(dlg)
		if err != nil {
			return nil, err
		}
		label.SetTextAlignment(walk.AlignHFarVCenter)
		label.SetText(item.caption)
		layout.SetRange(label, walk.Rectangle{0, row, 1, 1})

		value, err := walk.NewLineEdit(dlg)
		if err != nil {
			return nil, err
		}
		value.SetToolTipText(item.tooltip)
		layout.SetRange(value, walk.Rectangle{1, row, 1, 1})
		*item.target = value
		row++
	}

	methodLabel, err := walk.NewTextLabel(dlg)
	if err != nil {
		return nil, err
	}
	methodLabel.SetTextAlignment(walk.AlignHFarVCenter)
	methodLabel.SetText(l18n.Sprintf("Probe &method:"))
	layout.SetRange(methodLabel, walk.Rectangle{0, row, 1, 1})

	if dlg.method, err = walk.NewComboBox(dlg); err != nil {
		return nil, err
	}
	layout.SetRange(dlg.method, walk.Rectangle{1, row, 1, 1})
	if err := dlg.method.SetModel([]string{
		l18n.Sprintf("HTTP request (any answer counts)"),
		l18n.Sprintf("TCP connection"),
	}); err != nil {
		return nil, err
	}
	if setting.method == reconnect.MethodTCP {
		dlg.method.SetCurrentIndex(1)
	} else {
		dlg.method.SetCurrentIndex(0)
	}
	row++

	// Fill the text fields, leaving a field empty when its value is still the
	// default, so that "empty means default" stays visible.
	dlg.enabled.SetChecked(setting.enabled)
	dlg.target.SetText(dlg.config.Interface.ReconnectProbe)
	if dlg.config.Interface.ReconnectInterval > 0 {
		dlg.interval.SetText(strconv.Itoa(int(dlg.config.Interface.ReconnectInterval)))
	} else {
		_ = dlg.interval.SetCueBanner(strconv.Itoa(int(reconnect.DefaultInterval.Seconds())))
	}
	if dlg.config.Interface.ReconnectTimeout > 0 {
		dlg.timeout.SetText(strconv.Itoa(int(dlg.config.Interface.ReconnectTimeout)))
	} else {
		_ = dlg.timeout.SetCueBanner(strconv.Itoa(int(reconnect.DefaultTimeout.Seconds())))
	}
	if dlg.config.Interface.ReconnectThreshold > 0 {
		dlg.threshold.SetText(strconv.Itoa(int(dlg.config.Interface.ReconnectThreshold)))
	} else {
		_ = dlg.threshold.SetCueBanner(strconv.Itoa(reconnect.DefaultThreshold))
	}
	dlg.webhook.SetText(dlg.config.Interface.ReconnectWebhook)

	buttons, err := walk.NewComposite(dlg)
	if err != nil {
		return nil, err
	}
	layout.SetRange(buttons, walk.Rectangle{0, row, 2, 1})
	buttons.SetLayout(walk.NewHBoxLayout())
	buttons.Layout().SetMargins(walk.Margins{})

	walk.NewHSpacer(buttons)
	saveButton, err := walk.NewPushButton(buttons)
	if err != nil {
		return nil, err
	}
	saveButton.SetText(l18n.Sprintf("&Save"))
	saveButton.Clicked().Attach(dlg.onSave)
	cancelButton, err := walk.NewPushButton(buttons)
	if err != nil {
		return nil, err
	}
	cancelButton.SetText(l18n.Sprintf("Cancel"))
	cancelButton.Clicked().Attach(dlg.Cancel)
	dlg.SetCancelButton(cancelButton)
	dlg.SetDefaultButton(saveButton)

	disposables.Spare()
	return dlg, nil
}

func (dlg *reconnectSettingsDialog) onSave() {
	interval, err := parseOptionalNumber(dlg.interval.Text(), 1, 65535)
	if err != nil {
		showWarningCustom(dlg, l18n.Sprintf("Invalid probe interval"), err.Error())
		return
	}
	timeout, err := parseOptionalNumber(dlg.timeout.Text(), 1, 65535)
	if err != nil {
		showWarningCustom(dlg, l18n.Sprintf("Invalid probe timeout"), err.Error())
		return
	}
	threshold, err := parseOptionalNumber(dlg.threshold.Text(), 1, 65535)
	if err != nil {
		showWarningCustom(dlg, l18n.Sprintf("Invalid failure threshold"), err.Error())
		return
	}
	target := strings.TrimSpace(dlg.target.Text())
	if target != "" {
		if err := conf.ValidateProbeTarget(target); err != nil {
			showWarningCustom(dlg, l18n.Sprintf("Invalid probe target"), err.Error())
			return
		}
	}

	cfg := dlg.config
	cfg.Interface.AutoReconnectOff = !dlg.enabled.Checked()
	if dlg.method.CurrentIndex() == 1 {
		cfg.Interface.ReconnectMethod = string(reconnect.MethodTCP)
	} else {
		cfg.Interface.ReconnectMethod = string(reconnect.MethodHTTP)
	}
	cfg.Interface.ReconnectProbe = target
	cfg.Interface.ReconnectInterval = interval
	cfg.Interface.ReconnectTimeout = timeout
	cfg.Interface.ReconnectThreshold = threshold
	cfg.Interface.ReconnectWebhook = strings.TrimSpace(dlg.webhook.Text())

	dlg.config = cfg
	dlg.Accept()
}

// parseOptionalNumber reads a field that is allowed to be empty, in which case
// the setting keeps its default.
func parseOptionalNumber(text string, min, max int) (uint16, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, errors.New(l18n.Sprintf("‘%s’ is not a whole number", text))
	}
	if value < min || value > max {
		return 0, errors.New(l18n.Sprintf("The value has to be between %d and %d", min, max))
	}
	return uint16(value), nil
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"log"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
)

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, so sleeping for 4 seconds", name)
			continue
		}
		if err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() {
			log.Printf("Host not found when resolving %s at boot time, so sleeping for 4 seconds", name)
			continue
		}
		return
	}
	return
}

// resolveHostnameCandidates returns every address the system resolver offered,
// IPv4 addresses before IPv6 ones and each group in the order the resolver gave
// them, with duplicates removed.
//
// The list matters rather than just its first element because a name that is
// being repointed can briefly answer with the old address and the new one at
// the same time, and a caller that has already established the old address does
// not work wants to be able to pick the other one.
func resolveHostnameCandidates(name string) (addresses []string, err error) {
	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, windows.WSAHOST_NOT_FOUND
	}
	defer windows.FreeAddrInfoW(result)

	var v4, v6 []string
	seen := make(map[string]bool)
	for ; result != nil; result = result.Next {
		if result.Family != windows.AF_INET && result.Family != windows.AF_INET6 {
			continue
		}
		addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
		text := addr.String()
		if seen[text] {
			continue
		}
		seen[text] = true
		if addr.Is4() {
			v4 = append(v4, text)
		} else if addr.Is6() {
			v6 = append(v6, text)
		}
	}
	addresses = append(v4, v6...)
	if len(addresses) == 0 {
		return nil, windows.WSAHOST_NOT_FOUND
	}
	return addresses, nil
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
	addresses, err := resolveHostnameCandidates(name)
	if err != nil {
		return "", err
	}
	return addresses[0], nil
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		config.Peers[i].Endpoint.Host, err = resolveHostname(config.Peers[i].Endpoint.Host)
		if err != nil {
			return err
		}
	}
	return nil
}

// ResolveHostnameOnce performs a single, non-retrying lookup through the system
// resolver. Unlike resolveHostname it does not sleep and retry for up to forty
// seconds, which makes it suitable for runtime use where the caller drives its
// own retry and fallback policy.
func ResolveHostnameOnce(name string) (string, error) {
	return resolveHostnameOnce(name)
}

// ResolveHostnameCandidates is ResolveHostnameOnce without the narrowing: it
// hands back every address the resolver offered instead of the first one, so
// that a caller which already knows the first address is dead can pick another.
func ResolveHostnameCandidates(name string) ([]string, error) {
	return resolveHostnameCandidates(name)
}

// FlushResolverCache drops the DNS client resolver cache of the calling user.
// Endpoint hostnames are resolved once at tunnel startup, so without dropping
// the cache a changed A record can stay masked by the stale answer for as long
// as its TTL, which is exactly the case runtime endpoint re-resolution exists
// to handle.
func FlushResolverCache() error {
	dnsapi := windows.NewLazySystemDLL("dnsapi.dll")
	flush := dnsapi.NewProc("DnsFlushResolverCache")
	ret, _, err := flush.Call()
	if ret == 0 {
		return err
	}
	return nil
}

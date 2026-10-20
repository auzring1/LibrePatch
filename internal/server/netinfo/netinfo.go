// Package netinfo reads the network cards a device reported (the "interfaces" of its hardware snapshot).
package netinfo

import (
	"encoding/json"
	"net/netip"
	"strings"
)

// Iface is one network card as the agent reports it.
type Iface struct {
	Name      string   `json:"name"`
	Mac       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	Cidrs     []string `json:"cidrs"`
}

// Interfaces parses the hardware snapshot.
func Interfaces(hw []byte) []Iface {
	var h struct {
		Interfaces []Iface `json:"interfaces"`
	}
	_ = json.Unmarshal(hw, &h)
	return h.Interfaces
}

// Virtual spots adapters that never wake a computer or share a real network: virtual switches, VPNs, tunnels, Bluetooth.
func Virtual(n string) bool {
	n = strings.ToLower(n)
	for _, bad := range []string{"vethernet", "virtual", "vpn", "tunnel", "bluetooth", "loopback", "vmware", "vbox", "hyper-v", "tap-", "wireguard", "docker", "wsl", "tailscale", "zerotier"} {
		if strings.Contains(n, bad) {
			return true
		}
	}
	return false
}

// Network is an address of a device together with its network.
type Network struct {
	Addr   netip.Addr
	Prefix netip.Prefix // masked
}

// Networks lists the IPv4 networks of the real-looking cards that are at least four addresses large and no larger than /8.
func Networks(hw []byte) []Network {
	var out []Network
	for _, i := range Interfaces(hw) {
		if Virtual(i.Name) {
			continue
		}
		for _, c := range i.Cidrs {
			p, err := netip.ParsePrefix(c)
			if err != nil || !p.Addr().Is4() || p.Bits() > 30 || p.Bits() < 8 {
				continue
			}
			out = append(out, Network{Addr: p.Addr(), Prefix: p.Masked()})
		}
	}
	return out
}

// Addresses lists the IPv4 addresses (any card) a device reported.
func Addresses(hw []byte) []netip.Addr {
	var out []netip.Addr
	for _, i := range Interfaces(hw) {
		if Virtual(i.Name) {
			continue
		}
		for _, a := range i.Addresses {
			if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				out = append(out, ip)
			}
		}
	}
	return out
}

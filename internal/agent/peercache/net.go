package peercache

import "net"

// LocalNetworks lists the IPv4 networks of this computer's up, non-loopback interfaces.
func LocalNetworks() []*net.IPNet {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				out = append(out, &net.IPNet{IP: ipn.IP.Mask(ipn.Mask).To4(), Mask: ipn.Mask})
			}
		}
	}
	return out
}

// InAny reports whether ip lies in one of the networks.
func InAny(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

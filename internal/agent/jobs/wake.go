package jobs

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Wake-on-LAN (D125). The agent sends the "magic packet" for other computers on its own network. It never sends
// anywhere but the broadcast address of one of its own interfaces, and only for a computer whose last address lies
// in that interface's network, so a job cannot make it send packets to some other network.

const maxWakeTargets = 4

// LocalNet is one IPv4 address of this computer and its network.
type LocalNet struct {
	IP  net.IP
	Net *net.IPNet
}

// systemNets lists the up, non-loopback IPv4 networks of this computer.
func systemNets() []LocalNet {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []LocalNet
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				out = append(out, LocalNet{IP: ipn.IP.To4(), Net: &net.IPNet{IP: ipn.IP.Mask(ipn.Mask).To4(), Mask: ipn.Mask}})
			}
		}
	}
	return out
}

// sendUDP sends one datagram from the local address to dest ("ip:port").
func sendUDP(local net.IP, dest string, pkt []byte) error {
	raddr, err := net.ResolveUDPAddr("udp4", dest)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: local}, raddr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = c.Write(pkt)
	return err
}

// magicPacket is six 0xFF bytes followed by the MAC address sixteen times.
func magicPacket(mac net.HardwareAddr) []byte {
	return append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(mac, 16)...)
}

func broadcastOf(n *net.IPNet) net.IP {
	ip, m := n.IP.To4(), n.Mask
	if ip == nil || len(m) != 4 {
		return nil
	}
	b := make(net.IP, 4)
	for i := range b {
		b[i] = ip[i] | ^m[i]
	}
	return b
}

// parseWakeTarget validates one target.
func parseWakeTarget(t *agentv1.WakeTarget) (net.HardwareAddr, net.IP, error) {
	mac, err := net.ParseMAC(t.GetMac())
	if err != nil || len(mac) != 6 {
		return nil, nil, bad("a MAC address has six bytes")
	}
	if bytes.Equal(mac, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) || bytes.Equal(mac, make([]byte, 6)) || mac[0]&1 == 1 {
		return nil, nil, bad("not a computer's MAC address")
	}
	ip := net.ParseIP(t.GetLastIp()).To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return nil, nil, bad("the last address must be an IPv4 address")
	}
	return mac, ip, nil
}

// ValidateWake checks a wake job body.
func ValidateWake(b *agentv1.WakeBody) error {
	if b == nil || len(b.Targets) == 0 || len(b.Targets) > maxWakeTargets {
		return bad("a wake job names 1 to %d network cards", maxWakeTargets)
	}
	for _, t := range b.Targets {
		if _, _, err := parseWakeTarget(t); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) sendWake(ctx context.Context, env *agentv1.JobEnvelope) *outcome {
	nets := e.LocalNets
	if nets == nil {
		nets = systemNets
	}
	send := e.SendUDP
	if send == nil {
		send = sendUDP
	}
	local := nets()
	var sent []string
	var missed []string
	for _, t := range env.GetWake().Targets {
		mac, ip, err := parseWakeTarget(t)
		if err != nil {
			return fail("%v", err)
		}
		pkt := magicPacket(mac)
		did := false
		for _, ln := range local {
			ones, bits := ln.Net.Mask.Size()
			if bits != 32 || ones > 30 || !ln.Net.Contains(ip) {
				continue
			}
			bc := broadcastOf(ln.Net)
			for round := 0; round < 2; round++ {
				if round > 0 {
					e.sleep(ctx, 150*time.Millisecond)
				}
				for _, dest := range []string{net.JoinHostPort(bc.String(), "9"), net.JoinHostPort("255.255.255.255", "9")} {
					if err := send(ln.IP, dest, pkt); err != nil {
						e.log().Warn("wake packet not sent", "to", dest, "err", err)
						continue
					}
					did = true
				}
			}
			if did {
				sent = append(sent, fmt.Sprintf("%s on %s", strings.ToLower(mac.String()), ln.Net))
				break
			}
		}
		if !did {
			missed = append(missed, mac.String())
		}
	}
	if len(sent) == 0 {
		o := fail("this computer is not on the same network as %s, so it cannot wake it", strings.Join(missed, ", "))
		o.reason = "wrong_network"
		return o
	}
	msg := "sent Wake-on-LAN packets for " + strings.Join(sent, "; ")
	if len(missed) > 0 {
		msg += " (not on this network: " + strings.Join(missed, ", ") + ")"
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, Message: short(msg)}}
}

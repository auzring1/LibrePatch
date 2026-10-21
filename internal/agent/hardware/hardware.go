// Package hardware collects basic hardware/OS inventory and heartbeat data.
package hardware

import (
	"context"
	"crypto/sha256"
	"net"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Collector gathers inventory. Implementations must be cheap enough to run
// at background priority a few times a day.
type Collector interface {
	Collect(ctx context.Context) (*agentv1.HardwareInventory, error)
	Heartbeat(ctx context.Context) (*agentv1.Heartbeat, error)
}

// Fingerprint hashes the inventory excluding volatile values (free space,
// boot time) so trivial changes do not cause re-sends.
func Fingerprint(hw *agentv1.HardwareInventory) []byte {
	c := proto.Clone(hw).(*agentv1.HardwareInventory)
	c.BootTime = 0
	for _, d := range c.Disks {
		d.FreeBytes = 0
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	s := sha256.Sum256(b)
	return s[:]
}

// Interfaces lists up, non-loopback interfaces with their addresses.
func Interfaces() []*agentv1.NetInterface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []*agentv1.NetInterface
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		ni := &agentv1.NetInterface{Name: i.Name, Mac: i.HardwareAddr.String()}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				ni.Addresses = append(ni.Addresses, ipn.IP.String())
				ni.Cidrs = append(ni.Cidrs, ipn.String())
			}
		}
		if len(ni.Addresses) > 0 {
			slices.Sort(ni.Addresses)
			slices.Sort(ni.Cidrs)
			out = append(out, ni)
		}
		if len(out) >= 32 {
			break
		}
	}
	slices.SortFunc(out, func(a, b *agentv1.NetInterface) int { return strings.Compare(a.Name, b.Name) })
	return out
}

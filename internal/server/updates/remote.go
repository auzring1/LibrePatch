package updates

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Wake-on-LAN and read-only views of a device (D125).

// ErrAlreadyOnline: the device to wake is online.
var ErrAlreadyOnline = errNew("updates: the device is already online")

// ErrNoHelper: no other online computer can reach the device's network.
var ErrNoHelper = errNew("updates: no other online computer is on that network")

// ErrNoAddress: the device never reported a network card the server could wake.
var ErrNoAddress = errNew("updates: no network card address is known for this device")

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
func errNew(s string) error       { return simpleErr(s) }

type hwIface struct {
	Name      string   `json:"name"`
	Mac       string   `json:"mac"`
	Addresses []string `json:"addresses"`
	Cidrs     []string `json:"cidrs"`
}

func interfacesOf(hw []byte) []hwIface {
	var h struct {
		Interfaces []hwIface `json:"interfaces"`
	}
	_ = json.Unmarshal(hw, &h)
	return h.Interfaces
}

// virtualName spots adapters that never wake a computer: virtual switches, VPNs, tunnels, Bluetooth.
func virtualName(n string) bool {
	n = strings.ToLower(n)
	for _, bad := range []string{"vethernet", "virtual", "vpn", "tunnel", "bluetooth", "loopback", "vmware", "vbox", "hyper-v", "tap-", "wireguard", "docker", "wsl", "tailscale", "zerotier"} {
		if strings.Contains(n, bad) {
			return true
		}
	}
	return false
}

// WakeTargets are the network cards of a device that could be woken: a real-looking MAC and an IPv4 address, at most four.
func WakeTargets(hw []byte) []*agentv1.WakeTarget {
	var out []*agentv1.WakeTarget
	for _, i := range interfacesOf(hw) {
		if virtualName(i.Name) || len(i.Mac) != 17 {
			continue
		}
		for _, a := range i.Addresses {
			ip, err := netip.ParseAddr(a)
			if err != nil || !ip.Is4() || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsMulticast() {
				continue
			}
			out = append(out, &agentv1.WakeTarget{Mac: strings.ToLower(i.Mac), LastIp: ip.String()})
			break
		}
		if len(out) == 4 {
			break
		}
	}
	return out
}

// covered returns the targets whose address lies in one of the helper's networks (only networks of at least four addresses).
func covered(helperHW []byte, targets []*agentv1.WakeTarget) []*agentv1.WakeTarget {
	var nets []netip.Prefix
	for _, i := range interfacesOf(helperHW) {
		if virtualName(i.Name) {
			continue
		}
		for _, c := range i.Cidrs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() && p.Bits() <= 30 && p.Bits() >= 8 {
				nets = append(nets, p.Masked())
			}
		}
	}
	var out []*agentv1.WakeTarget
	for _, t := range targets {
		ip, _ := netip.ParseAddr(t.LastIp)
		for _, n := range nets {
			if n.Contains(ip) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// WakeDevice sends a Wake-on-LAN packet for an offline device through another online device on the same network.
// It returns the id of the job (which belongs to the helper) and the helper's host name.
func (s *Service) WakeDevice(ctx context.Context, a Actor, device uuid.UUID) (uuid.UUID, string, error) {
	d, err := s.device(ctx, a.Org, device)
	if err != nil {
		return uuid.Nil, "", err
	}
	if d.Online {
		return uuid.Nil, "", ErrAlreadyOnline
	}
	targets := WakeTargets(d.Hardware)
	if len(targets) == 0 {
		return uuid.Nil, "", ErrNoAddress
	}
	q := dbq.New(s.Pool)
	helpers, err := q.ListWakeHelpers(ctx, dbq.ListWakeHelpersParams{OrgID: a.Org, ID: d.ID})
	if err != nil {
		return uuid.Nil, "", err
	}
	type cand struct {
		h   dbq.ListWakeHelpersRow
		got []*agentv1.WakeTarget
	}
	var cands []cand
	for _, h := range helpers {
		if got := covered(h.Hardware, targets); len(got) > 0 {
			cands = append(cands, cand{h, got})
		}
	}
	if len(cands) == 0 {
		return uuid.Nil, "", ErrNoHelper
	}
	// Most cards reached first, then the same site, then the name (the query is already ordered by name).
	sort.SliceStable(cands, func(i, j int) bool {
		if len(cands[i].got) != len(cands[j].got) {
			return len(cands[i].got) > len(cands[j].got)
		}
		return (cands[i].h.SiteID == d.SiteID) && (cands[j].h.SiteID != d.SiteID)
	})
	best := cands[0]
	now := s.now()
	job, err := s.Deploy.NewJob(a.Org, best.h.ID, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_WAKE, DBType: "wake", Title: "Wake " + clean(d.Hostname, 100),
		NotBefore: now, Expires: now.Add(10 * time.Minute), Body: &agentv1.WakeBody{Targets: best.got}})
	if err != nil {
		return uuid.Nil, "", err
	}
	err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.InsertJob(ctx, job); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "device.wake",
			TargetType: "device", TargetIDs: []string{d.ID.String()}, Outcome: audit.Success,
			Details: map[string]any{"hostname": d.Hostname, "helper": best.h.Hostname, "helper_id": best.h.ID.String(), "cards": len(best.got)}}, now)
		return err
	})
	if err != nil {
		return uuid.Nil, "", err
	}
	s.Deploy.Publish(a.Org, "job.updated", best.h.ID, job.ID, uuid.Nil)
	s.Deploy.DispatchAsync(best.h.ID)
	return job.ID, best.h.Hostname, nil
}

// InspectRequest is what an administrator asks to see.
type InspectRequest struct {
	Kind         string `json:"kind"` // processes | services | events
	Log          string `json:"log"`
	MaxLevel     int    `json:"max_level"`
	SinceMinutes int    `json:"since_minutes"`
	MaxEvents    int    `json:"max_events"`
}

// InspectDevice asks an online device for a read-only view of itself.
func (s *Service) InspectDevice(ctx context.Context, a Actor, device uuid.UUID, r InspectRequest) (uuid.UUID, error) {
	body := &agentv1.InspectBody{}
	details := map[string]any{"kind": r.Kind}
	title := ""
	switch r.Kind {
	case "processes":
		body.Kind, title = agentv1.InspectKind_INSPECT_KIND_PROCESSES, "Show running programs"
	case "services":
		body.Kind, title = agentv1.InspectKind_INSPECT_KIND_SERVICES, "Show services"
	case "events":
		if r.Log != "" && r.Log != "System" && r.Log != "Application" && r.Log != "Setup" {
			return uuid.Nil, invalid("the event log must be System, Application or Setup")
		}
		if r.MaxLevel < 0 || r.MaxLevel > 5 || r.SinceMinutes < 0 || r.SinceMinutes > 10080 || r.MaxEvents < 0 || r.MaxEvents > 200 {
			return uuid.Nil, invalid("event view limits out of range")
		}
		body.Kind, body.Log = agentv1.InspectKind_INSPECT_KIND_EVENTS, r.Log
		body.MaxLevel, body.SinceMinutes, body.MaxEvents = uint32(r.MaxLevel), uint32(r.SinceMinutes), uint32(r.MaxEvents) // #nosec G115 -- range checked above
		title = "Show event log"
		details["log"] = r.Log
	default:
		return uuid.Nil, invalid("kind must be processes, services or events")
	}
	d, err := s.device(ctx, a.Org, device)
	if err != nil {
		return uuid.Nil, err
	}
	if !d.Online {
		return uuid.Nil, ErrOffline
	}
	now := s.now()
	return s.enqueue(ctx, a, d, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_INSPECT, DBType: "inspect", Title: title, NotBefore: now, Expires: now.Add(5 * time.Minute), Body: body},
		"device.inspect", details, nil)
}

// View is what a read-only view returned (or why it has not yet).
type View struct {
	Status string          `json:"status"`
	Reason string          `json:"status_reason"`
	Kind   string          `json:"kind,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// GetView returns the state of an inspect job and, when it succeeded, its data (kept for an hour).
func (s *Service) GetView(ctx context.Context, org, device, job uuid.UUID) (*View, error) {
	q := dbq.New(s.Pool)
	j, err := q.GetJobForDevice(ctx, dbq.GetJobForDeviceParams{ID: job, DeviceID: device})
	if err != nil || j.OrgID != org || j.Type != "inspect" {
		return nil, ErrNotFound
	}
	v := &View{Status: j.Status, Reason: j.StatusReason}
	if j.Status == "succeeded" {
		if dv, err := q.GetDeviceView(ctx, dbq.GetDeviceViewParams{JobID: job, OrgID: org, DeviceID: device}); err == nil {
			v.Kind, v.Data = dv.Kind, dv.Data
		}
	}
	return v, nil
}

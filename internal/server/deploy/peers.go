package deploy

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/netinfo"
)

// Sharing downloaded installers between computers on one network (D126): when the organization has turned it on, the
// installer sources of a job get a few peers in front of the usual ones.

const (
	maxPeerSources = 3
	// agentMaxSources is how many content sources the agent accepts in one job (jobs.MaxSources).
	agentMaxSources = 4
	peerMemory      = 14 * 24 * time.Hour
)

// peerSources returns up to three peers for the device that will run the job: online devices that share downloads, have
// installed from the same file, and have an address in a network the target is on. The URL uses the peer's address in that network.
func (s *Service) peerSources(ctx context.Context, j dbq.Job, in *agentv1.InstallBody) []*agentv1.ContentSource {
	if in.GetInstaller() == nil || len(in.Installer.Sha256) != 32 {
		return nil
	}
	q := dbq.New(s.Pool)
	target, err := q.GetDevice(ctx, j.DeviceID)
	if err != nil {
		return nil
	}
	mine := netinfo.Addresses(target.Hardware)
	if len(mine) == 0 {
		return nil
	}
	cands, err := q.ListPeerCandidates(ctx, dbq.ListPeerCandidatesParams{Sha256: in.Installer.Sha256, SeenAt: s.now().Add(-peerMemory), OrgID: j.OrgID, ID: j.DeviceID})
	if err != nil {
		return nil
	}
	limit := min(maxPeerSources, agentMaxSources-len(in.Installer.Sources))
	var out []*agentv1.ContentSource
	for _, c := range cands {
		if len(out) >= limit {
			break
		}
		if c.PeerPort < 1024 || c.PeerPort > 65535 {
			continue
		}
		if ip, ok := sharedNetworkAddr(c.Hardware, mine); ok {
			out = append(out, &agentv1.ContentSource{Kind: agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_PEER, Url: fmt.Sprintf("https://%s:%d", ip, c.PeerPort)})
		}
	}
	return out
}

// sharedNetworkAddr returns the peer's address in a private network that also holds one of the target's addresses.
func sharedNetworkAddr(peerHW []byte, target []netip.Addr) (netip.Addr, bool) {
	for _, n := range netinfo.Networks(peerHW) {
		if !n.Addr.IsPrivate() {
			continue
		}
		for _, t := range target {
			if t != n.Addr && n.Prefix.Contains(t) {
				return n.Addr, true
			}
		}
	}
	return netip.Addr{}, false
}

// notePeerContent records that a device installed from a file, so it can be offered as a peer for it.
func notePeerContent(ctx context.Context, q *dbq.Queries, device uuid.UUID, body []byte, now time.Time) error {
	sha := installerSHA(body)
	if sha == nil {
		return nil
	}
	_ = q.PrunePeerContent(ctx, now.Add(-2*peerMemory))
	return q.UpsertPeerContent(ctx, dbq.UpsertPeerContentParams{DeviceID: device, Sha256: sha, SeenAt: now})
}

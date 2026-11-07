package gateway

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/events"
	"github.com/auzring1/librepatch/internal/server/inventory"
	"github.com/auzring1/librepatch/internal/server/updates"
)

// maxChunks bounds a full software snapshot: MaxItems at the agent's chunk size
// with generous slack for other chunk sizes.
const maxChunks = 400

// chunkStage collects the chunks of one full software snapshot. It lives on
// the connection, so a dropped stream discards a half-received snapshot.
type chunkStage struct {
	rev       uint64
	truncated bool
	next      uint32
	total     uint32
	items     []*agentv1.SoftwareItem
}

// invAllowed applies the per-device inventory message rate limit.
func (g *Gateway) invAllowed(c *conn) bool { return g.invDevice.Allow(c.deviceID.String()) }

// handleInventory processes SOFTWARE and USERS reports. A rejected report
// ends the stream (the agent reconnects with back-off); a revision mismatch
// instead asks the agent for a full resync and does not acknowledge.
func (g *Gateway) handleInventory(ctx context.Context, c *conn, dev dbq.Device, inv *agentv1.InventoryReport) error {
	if !g.invAllowed(c) {
		g.securityAudit(ctx, dev, "inventory_rate_limit")
		return status.Error(codes.ResourceExhausted, "inventory rate limit")
	}
	var err error
	switch inv.Section {
	case agentv1.InventorySection_INVENTORY_SECTION_USERS:
		u := inv.GetUsers()
		if u == nil {
			return status.Error(codes.InvalidArgument, "users report without body")
		}
		err = g.inv.ApplyUsers(ctx, dev.ID, inv.Rev, u.Users)
	case agentv1.InventorySection_INVENTORY_SECTION_WU:
		w := inv.GetWu()
		if w == nil || g.updates == nil {
			return status.Error(codes.InvalidArgument, "windows update report without body")
		}
		err = g.updates.ApplySnapshot(ctx, dev, inv.Rev, w)
	case agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE:
		var done bool
		if done, err = g.handleSoftware(ctx, c, inv); err == nil && !done {
			return nil // intermediate chunk: acknowledged with the last one
		}
	default:
		return status.Error(codes.InvalidArgument, "unsupported inventory section")
	}
	switch {
	case err == nil:
	case errors.Is(err, inventory.ErrRevMismatch):
		g.log.Info("software revision mismatch; requesting resync", "device", dev.ID)
		return c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_Resync{Resync: &agentv1.ResyncRequest{
			Section: agentv1.InventorySection_INVENTORY_SECTION_SOFTWARE}}})
	case errors.Is(err, updates.ErrInvalid):
		g.securityAudit(ctx, dev, "invalid_windows_update_data: "+cleanField(err.Error(), 200))
		return status.Error(codes.InvalidArgument, "invalid windows update data")
	case errors.Is(err, inventory.ErrInvalid):
		g.securityAudit(ctx, dev, "invalid_inventory: "+cleanField(err.Error(), 200))
		return status.Error(codes.InvalidArgument, "invalid inventory data")
	default:
		return err
	}
	if err := c.send(&agentv1.ConnectResponse{Msg: &agentv1.ConnectResponse_Ack{Ack: &agentv1.Ack{Seq: inv.Seq}}}); err != nil {
		return err
	}
	g.events.Publish(dev.OrgID, events.Event{Type: events.DeviceUpdated, DeviceID: dev.ID})
	return nil
}

// handleSoftware applies a delta, or stages a chunk and applies the snapshot
// when the last one arrives. done reports whether anything was applied.
func (g *Gateway) handleSoftware(ctx context.Context, c *conn, inv *agentv1.InventoryReport) (done bool, err error) {
	if d := inv.GetSoftwareDelta(); d != nil {
		c.stage = nil // a delta abandons any half-received snapshot
		return true, g.inv.ApplyDelta(ctx, c.deviceID, inv.Rev, d, inv.Truncated)
	}
	ch := inv.GetSoftwareChunk()
	if ch == nil {
		return false, status.Error(codes.InvalidArgument, "software report without body")
	}
	if ch.Index == 0 {
		if ch.Total == 0 || ch.Total > maxChunks {
			return false, status.Error(codes.InvalidArgument, "bad chunk count")
		}
		c.stage = &chunkStage{rev: inv.Rev, truncated: inv.Truncated, total: ch.Total}
	}
	st := c.stage
	if st == nil || ch.Index != st.next || ch.Total != st.total || inv.Rev != st.rev {
		c.stage = nil
		return false, status.Error(codes.InvalidArgument, "out-of-order software chunk")
	}
	if len(st.items)+len(ch.Items) > inventory.MaxItems {
		c.stage = nil
		return false, status.Error(codes.InvalidArgument, "too many software items")
	}
	st.items = append(st.items, ch.Items...)
	st.next++
	if st.next < st.total {
		return false, nil
	}
	c.stage = nil
	return true, g.inv.ApplySnapshot(ctx, c.deviceID, st.rev, st.items, st.truncated)
}

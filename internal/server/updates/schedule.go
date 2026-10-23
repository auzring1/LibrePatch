package updates

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/rings"
	"github.com/auzring1/librepatch/internal/server/store"
)

// Tick is the periodic housekeeping: send source settings to devices, apply auto-approval rules
// and start the installs that the rings allow. Run it about once a minute.
func (s *Service) Tick(ctx context.Context) {
	ids, err := dbq.New(s.Pool).ListOrgIDs(ctx)
	if err != nil {
		s.log().Error("list organizations", "err", err)
		return
	}
	for _, org := range ids {
		if ctx.Err() != nil {
			return
		}
		if !s.On(ctx, org) {
			continue
		}
		s.ensureSettings(ctx, org)
		if err := s.applyRules(ctx, org); err != nil {
			s.log().Error("apply update rules", "org", org, "err", err)
		}
		if err := s.scheduleRings(ctx, org); err != nil {
			s.log().Error("schedule update rings", "org", org, "err", err)
		}
	}
}

// Prune forgets updates nobody has reported for a long time.
func (s *Service) Prune(ctx context.Context) {
	if n, err := dbq.New(s.Pool).PruneWuUpdates(ctx); err != nil {
		s.log().Error("prune updates", "err", err)
	} else if n > 0 {
		s.log().Debug("old updates removed", "count", n)
	}
}

// ensureSettings sends a scan job carrying the organization's source settings to every online
// device that has not received the current ones (new devices, or after a settings change).
func (s *Service) ensureSettings(ctx context.Context, org uuid.UUID) {
	q := dbq.New(s.Pool)
	cfg := s.settings(ctx, org)
	ids, err := q.ListDevicesNeedingWUSettings(ctx, org)
	if err == nil && len(ids) == 0 {
		ids, err = q.ListDevicesNeedingWUSettingsNoRow(ctx, org)
	}
	if err != nil {
		s.log().Error("list devices needing update settings", "err", err)
		return
	}
	now := s.now()
	for _, id := range ids {
		job, err := s.Deploy.NewJob(org, id, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_WU_SCAN, DBType: "wu_scan", Title: "Scan for Windows updates",
			NotBefore: now, Expires: now.Add(24 * time.Hour), Body: &agentv1.WuScanBody{Service: cfg.service, IncludeDrivers: cfg.drivers}})
		if err != nil {
			continue
		}
		err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
			if err := q.InsertJob(ctx, job); err != nil {
				return err
			}
			return q.SetDeviceWUSettingsRev(ctx, dbq.SetDeviceWUSettingsRevParams{ID: id, WuSettingsRev: cfg.rev})
		})
		if err != nil {
			s.log().Error("queue scan job", "device", id, "err", err)
			continue
		}
		s.Deploy.DispatchAsync(id)
	}
}

// ---- auto-approval ----

func ruleMatches(r dbq.WuRule, u dbq.WuUpdate, now time.Time) bool {
	if !r.Enabled {
		return false
	}
	if u.IsDriver && !r.IncludeDrivers {
		return false
	}
	if len(r.Classifications) > 0 {
		ok := false
		for _, c := range r.Classifications {
			ok = ok || strings.EqualFold(c, u.Classification)
		}
		if !ok {
			return false
		}
	}
	if len(r.Severities) > 0 {
		sev := u.Severity
		if sev == "" {
			sev = "Unrated"
		}
		ok := false
		for _, c := range r.Severities {
			ok = ok || c == sev
		}
		if !ok {
			return false
		}
	}
	released := u.FirstSeenAt
	if u.ReleaseDate != nil {
		released = *u.ReleaseDate
	}
	return !now.Before(released.Add(time.Duration(r.DelayDays) * 24 * time.Hour))
}

// applyRules approves, once, the updates that an enabled rule matches. Administrators' own
// decisions (including a decline) are never overridden: only updates without a decision are looked at.
func (s *Service) applyRules(ctx context.Context, org uuid.UUID) error {
	q := dbq.New(s.Pool)
	rules, err := q.ListRules(ctx, org)
	if err != nil || len(rules) == 0 {
		return err
	}
	ups, err := q.ListUnreviewedUpdates(ctx, org)
	if err != nil || len(ups) == 0 {
		return err
	}
	now := s.now()
	approved := map[uuid.UUID][]string{}
	for _, u := range ups {
		for _, r := range rules {
			if !ruleMatches(r, u, now) {
				continue
			}
			n, err := q.InsertRuleApproval(ctx, dbq.InsertRuleApprovalParams{OrgID: org, UpdateID: u.UpdateID, RuleID: &r.ID, Note: "rule: " + r.Name})
			if err != nil {
				return err
			}
			if n > 0 {
				approved[r.ID] = append(approved[r.ID], u.UpdateID.String())
			}
			break
		}
	}
	if len(approved) == 0 {
		return nil
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		for rule, list := range approved {
			shown := list
			if len(shown) > 50 {
				shown = shown[:50]
			}
			if _, err := audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: "update-rules", Action: "wu.auto_approve",
				TargetType: "wu_rule", TargetIDs: []string{rule.String()}, Outcome: audit.Success,
				Details: map[string]any{"count": len(list), "updates": shown}}, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- rings ----

type attemptStats struct {
	total, installed, failed int
	first                    time.Time
}

type holdState struct{ open, released bool }

// ringMembers returns the active devices of a ring's groups (cached for a few minutes).
func (s *Service) ringMembers(ctx context.Context, org uuid.UUID, r dbq.WuRing) (map[uuid.UUID]bool, error) {
	s.mu.Lock()
	if s.rings == nil {
		s.rings = map[uuid.UUID]ringCache{}
	}
	if c, ok := s.rings[r.ID]; ok && c.version.Equal(r.UpdatedAt) && s.now().Sub(c.at) < ringCacheTTL {
		s.mu.Unlock()
		return c.members, nil
	}
	s.mu.Unlock()
	devs, err := s.Deploy.ResolveTargets(ctx, org, r.GroupIds, nil)
	if err != nil {
		return nil, err
	}
	m := make(map[uuid.UUID]bool, len(devs))
	for _, d := range devs {
		m[d.ID] = true
	}
	s.mu.Lock()
	s.rings[r.ID] = ringCache{at: s.now(), version: r.UpdatedAt, members: m}
	s.mu.Unlock()
	return m, nil
}

// gate is the shared ring rule (internal/server/rings) applied to this package's types.
func gate(st attemptStats, ring dbq.WuRing, h holdState, now time.Time, needs bool) (passed bool, holdReason string) {
	return rings.Gate(rings.Stats{Total: st.total, Installed: st.installed, Failed: st.failed, First: st.first},
		rings.Ring{Name: ring.Name, SoakHours: ring.SoakHours, SuccessThreshold: ring.SuccessThreshold},
		rings.HoldState{Open: h.open, Released: h.released}, now, needs)
}

type approvedUpdate struct {
	id         uuid.UUID
	revision   int32
	approvedAt time.Time
	title      string
}

func (s *Service) scheduleRings(ctx context.Context, org uuid.UUID) error {
	q := dbq.New(s.Pool)
	all, err := q.ListRings(ctx, org)
	if err != nil {
		return err
	}
	var rings []dbq.WuRing
	for _, r := range all {
		if r.Enabled {
			rings = append(rings, r)
		}
	}
	if len(rings) == 0 {
		return nil
	}
	ap, err := q.ListApprovedUpdates(ctx, org)
	if err != nil || len(ap) == 0 {
		return err
	}
	approved := make([]approvedUpdate, 0, len(ap))
	ids := make([]uuid.UUID, 0, len(ap))
	for _, a := range ap {
		approved = append(approved, approvedUpdate{a.UpdateID, a.Revision, a.DecidedAt, a.Title})
		ids = append(ids, a.UpdateID)
	}
	atts, err := q.ListAttemptsForUpdates(ctx, dbq.ListAttemptsForUpdatesParams{OrgID: org, UpdateIds: ids})
	if err != nil {
		return err
	}
	type key struct{ update, ring uuid.UUID }
	stats := map[key]*attemptStats{}
	byPair := map[[2]uuid.UUID]dbq.ListAttemptsForUpdatesRow{}
	for _, a := range atts {
		byPair[[2]uuid.UUID{a.UpdateID, a.DeviceID}] = a
		if a.RingID == nil {
			continue
		}
		st := stats[key{a.UpdateID, *a.RingID}]
		if st == nil {
			st = &attemptStats{first: a.CreatedAt}
			stats[key{a.UpdateID, *a.RingID}] = st
		}
		st.total++
		switch a.State {
		case "installed":
			st.installed++
		case "failed":
			st.failed++
		}
		if a.CreatedAt.Before(st.first) {
			st.first = a.CreatedAt
		}
	}
	holdRows, err := q.ListAllHoldsForUpdates(ctx, dbq.ListAllHoldsForUpdatesParams{OrgID: org, UpdateIds: ids})
	if err != nil {
		return err
	}
	holds := map[key]holdState{}
	for _, h := range holdRows {
		hs := holds[key{h.UpdateID, h.RingID}]
		if h.ReleasedAt == nil {
			hs.open = true
		} else {
			hs.released = true
		}
		holds[key{h.UpdateID, h.RingID}] = hs
	}
	now := s.now()
	// Devices belong to the first ring that lists them.
	devRing := map[uuid.UUID]int{}
	devsOf := make([][]uuid.UUID, len(rings))
	for i, ring := range rings {
		members, err := s.ringMembers(ctx, org, ring)
		if err != nil {
			return err
		}
		for d := range members {
			if _, ok := devRing[d]; !ok {
				devRing[d] = i
				devsOf[i] = append(devsOf[i], d)
			}
		}
	}
	// What each ring device is missing among the approved updates.
	missingOf := map[uuid.UUID][]miss{}
	needs := make([]map[uuid.UUID]bool, len(rings))
	for i := range rings {
		needs[i] = map[uuid.UUID]bool{}
		for start := 0; start < len(devsOf[i]); start += 500 {
			end := min(start+500, len(devsOf[i]))
			rows, err := q.ListMissingForDevices(ctx, dbq.ListMissingForDevicesParams{DeviceIds: devsOf[i][start:end], UpdateIds: ids})
			if err != nil {
				return err
			}
			for _, m := range rows {
				missingOf[m.DeviceID] = append(missingOf[m.DeviceID], miss{m.UpdateID, m.Revision})
				if a, ok := byPair[[2]uuid.UUID{m.UpdateID, m.DeviceID}]; !ok || a.State != "installed" {
					needs[i][m.UpdateID] = true
				}
			}
		}
	}
	// Which updates may each ring install right now?
	eligible := make([]map[uuid.UUID]bool, len(rings))
	for i := range eligible {
		eligible[i] = map[uuid.UUID]bool{}
	}
	for _, u := range approved {
		passed := true
		for i, ring := range rings {
			elig := passed && !now.Before(u.approvedAt.Add(time.Duration(ring.DelayDays)*24*time.Hour))
			if elig {
				eligible[i][u.id] = true
			}
			passed = false
			if !elig {
				continue
			}
			var st attemptStats
			if p := stats[key{u.id, ring.ID}]; p != nil {
				st = *p
			}
			ok, reason := gate(st, ring, holds[key{u.id, ring.ID}], now, needs[i][u.id])
			if reason != "" {
				s.raiseHold(ctx, org, u, ring, reason)
			}
			passed = ok
		}
	}
	busyRows, err := q.ListActiveWUDevices(ctx, org)
	if err != nil {
		return err
	}
	busy := map[uuid.UUID]bool{}
	for _, d := range busyRows {
		busy[d] = true
	}
	cfg := s.settings(ctx, org)
	created := 0
	for i, ring := range rings {
		if len(eligible[i]) == 0 || created >= maxJobsPerTick {
			continue
		}
		n, err := s.dispatchRing(ctx, org, ring, cfg, devsOf[i], busy, eligible[i], missingOf, byPair, now, maxJobsPerTick-created)
		if err != nil {
			return err
		}
		created += n
	}
	return nil
}

func (s *Service) raiseHold(ctx context.Context, org uuid.UUID, u approvedUpdate, ring dbq.WuRing, reason string) {
	now := s.now()
	raised := false
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.InsertHold(ctx, dbq.InsertHoldParams{ID: uuid.New(), OrgID: org, UpdateID: u.id, RingID: ring.ID, Reason: reason})
		if err != nil || n == 0 {
			return err
		}
		raised = true
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: "update-rings", Action: "wu.hold",
			TargetType: "update", TargetIDs: []string{u.id.String()}, Outcome: audit.Success,
			Details: map[string]any{"title": u.title, "ring": ring.Name, "reason": reason}}, now)
		return err
	})
	if err != nil {
		s.log().Error("raise hold", "update", u.id, "err", err)
		return
	}
	if raised && s.OnHold != nil {
		s.OnHold(ctx, org, u.title, ring.Name, reason)
	}
	s.publish(org, uuid.Nil)
}

// miss is one update a device is missing.
type miss struct {
	update   uuid.UUID
	revision int32
}

// dispatchRing creates one install job per device of the ring for the eligible updates it misses.
func (s *Service) dispatchRing(ctx context.Context, org uuid.UUID, ring dbq.WuRing, cfg orgWU, devs []uuid.UUID, busy map[uuid.UUID]bool,
	eligible map[uuid.UUID]bool, missing map[uuid.UUID][]miss, attempts map[[2]uuid.UUID]dbq.ListAttemptsForUpdatesRow, now time.Time, budget int) (int, error) {
	win, err := ringWindow(ring)
	if err != nil {
		return 0, err
	}
	reboot := ringReboot(ring)
	created := 0
	for _, dev := range devs {
		if created >= budget {
			break
		}
		if busy[dev] {
			continue
		}
		var refs []*agentv1.WuUpdateRef
		for _, m := range missing[dev] {
			if !eligible[m.update] {
				continue
			}
			if a, ok := attempts[[2]uuid.UUID{m.update, dev}]; ok {
				switch a.State {
				case "queued", "installed":
					continue
				case "failed":
					// Not again today, and not forever.
					if a.Failures >= maxAutoFailures || (a.FinishedAt != nil && now.Sub(*a.FinishedAt) < retryFailedAfter) {
						continue
					}
				}
			}
			if len(refs) < maxUpdatesPerJob {
				refs = append(refs, &agentv1.WuUpdateRef{UpdateId: m.update.String(), Revision: m.revision})
			}
		}
		if len(refs) == 0 {
			continue
		}
		body := &agentv1.WuInstallBody{Service: cfg.service, IncludeDrivers: cfg.drivers, Updates: refs, Reboot: reboot.Proto(now),
			TimeoutS: 3 * 3600, MaxRetries: 2, RetryBackoffS: 300}
		job, err := s.Deploy.NewJob(org, dev, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_WU_INSTALL, DBType: "wu_install",
			Title: fmt.Sprintf("Install %d Windows update(s) (%s)", len(refs), ring.Name), Body: body, NotBefore: now, Expires: now.Add(jobLifetime), Window: win})
		if err != nil {
			return created, err
		}
		ringID := ring.ID
		err = store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
			if err := q.InsertJob(ctx, job); err != nil {
				return err
			}
			for _, r := range refs {
				uid, _ := uuid.Parse(r.UpdateId)
				if err := q.UpsertAttemptQueued(ctx, dbq.UpsertAttemptQueuedParams{OrgID: org, UpdateID: uid, DeviceID: dev, RingID: &ringID, JobID: &job.ID, At: now}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			s.log().Error("queue update install", "device", dev, "err", err)
			continue
		}
		created++
		s.Deploy.Publish(org, "job.updated", dev, job.ID, uuid.Nil)
		s.Deploy.DispatchAsync(dev)
	}
	if created > 0 {
		s.log().Info("windows update installs queued", "ring", ring.Name, "jobs", created)
		s.publish(org, uuid.Nil)
	}
	return created, nil
}

func ringWindow(r dbq.WuRing) (*agentv1.MaintenanceWindow, error) {
	v := ringView(r)
	return deploy.WindowProto(v.Window)
}

func ringReboot(r dbq.WuRing) RebootCfg { return ringView(r).Reboot }

// AfterJob updates install attempts when a Windows Update job ends (hooked into deploy.Service).
// Per-update results decide each attempt; a job that ended without them fails all of its updates,
// except expiry and cancellation, which only release the updates to be planned again.
func (s *Service) AfterJob(ctx context.Context, j dbq.Job, status string, u *agentv1.JobUpdate) {
	if j.Type != "wu_install" {
		return
	}
	q := dbq.New(s.Pool)
	switch status {
	case "expired", "cancelled":
		if err := q.DeleteQueuedAttemptsOfJob(ctx, &j.ID); err != nil {
			s.log().Error("release attempts", "job", j.ID, "err", err)
		}
		s.publish(j.OrgID, j.DeviceID)
		return
	}
	var env agentv1.JobEnvelope
	if proto.Unmarshal(j.Body, &env) != nil || env.GetWuInstall() == nil {
		return
	}
	results := map[string]*agentv1.WuUpdateResult{}
	if u != nil && u.Result != nil {
		for _, r := range u.Result.WuResults {
			results[strings.ToLower(r.UpdateId)] = r
		}
	}
	for _, ref := range env.GetWuInstall().Updates {
		id, err := uuid.Parse(ref.UpdateId)
		if err != nil {
			continue
		}
		state, hr := "failed", int32(0)
		if r := results[strings.ToLower(ref.UpdateId)]; r != nil {
			hr = r.Hresult
			switch r.Result {
			case agentv1.WuResult_WU_RESULT_INSTALLED, agentv1.WuResult_WU_RESULT_INSTALLED_REBOOT, agentv1.WuResult_WU_RESULT_NOT_APPLICABLE:
				state = "installed"
			}
		} else if status == "succeeded" || status == "succeeded_reboot" {
			state = "installed"
		}
		if err := q.SetAttemptResult(ctx, dbq.SetAttemptResultParams{OrgID: j.OrgID, UpdateID: id, DeviceID: j.DeviceID, JobID: &j.ID, State: state, Hresult: hr, At: s.now()}); err != nil {
			s.log().Error("record install result", "job", j.ID, "err", err)
		}
	}
	s.publish(j.OrgID, j.DeviceID)
}

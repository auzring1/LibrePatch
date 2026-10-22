package updates

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/store"
)

// DecideResult says what a decision did.
type DecideResult struct {
	Changed  int `json:"changed"`
	Missing  int `json:"missing"`   // ids that are not in the catalog
	HideJobs int `json:"hide_jobs"` // jobs queued to hide or unhide the update on devices
}

// Decide records an approval, decline or hide for updates, or resets them to pending ("none").
// Hiding queues WU_HIDE jobs on devices that miss the update; leaving the hidden state queues the
// matching unhide. Every call is one audit entry (manual overrides are always audited).
func (s *Service) Decide(ctx context.Context, a Actor, ids []uuid.UUID, decision, note string) (*DecideResult, error) {
	switch decision {
	case "approved", "declined", "hidden", "none":
	default:
		return nil, invalid("decision must be approved, declined, hidden or none")
	}
	if len(ids) == 0 || len(ids) > 200 {
		return nil, invalid("choose between 1 and 200 updates")
	}
	note = clean(strings.TrimSpace(note), 500)
	now := s.now()
	res := &DecideResult{}
	type hide struct {
		update uuid.UUID
		hide   bool
	}
	var hides []hide
	var changed []string
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		for _, id := range ids {
			if _, err := q.GetUpdate(ctx, dbq.GetUpdateParams{OrgID: a.Org, UpdateID: id}); err != nil {
				res.Missing++
				continue
			}
			prev := ""
			if p, err := q.GetApproval(ctx, dbq.GetApprovalParams{OrgID: a.Org, UpdateID: id}); err == nil {
				prev = p.Decision
			}
			if decision == "none" {
				if err := q.DeleteApproval(ctx, dbq.DeleteApprovalParams{OrgID: a.Org, UpdateID: id}); err != nil {
					return err
				}
			} else if err := q.UpsertApproval(ctx, dbq.UpsertApprovalParams{OrgID: a.Org, UpdateID: id, Decision: decision, Source: "manual", Note: note, DecidedBy: &a.User}); err != nil {
				return err
			}
			res.Changed++
			if len(changed) < 50 {
				changed = append(changed, id.String())
			}
			switch {
			case decision == "hidden" && prev != "hidden":
				hides = append(hides, hide{id, true})
			case decision != "hidden" && prev == "hidden":
				hides = append(hides, hide{id, false})
			}
		}
		if res.Changed == 0 {
			return nil
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP,
			Action: "wu.decision", TargetType: "update", TargetIDs: changed, Outcome: audit.Success,
			Details: map[string]any{"decision": decision, "count": res.Changed, "note": note}}, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	// Hide or unhide on the devices that have the update.
	for _, h := range hides {
		n, err := s.hideEverywhere(ctx, a, h.update, h.hide)
		if err != nil {
			s.log().Error("queue hide jobs", "update", h.update, "err", err)
			continue
		}
		res.HideJobs += n
	}
	s.publish(a.Org, uuid.Nil)
	return res, nil
}

// hideEverywhere queues a hide (or unhide) job on every active device whose last scan lists the update.
func (s *Service) hideEverywhere(ctx context.Context, a Actor, update uuid.UUID, hide bool) (int, error) {
	if !s.On(ctx, a.Org) {
		return 0, ErrDisabled
	}
	q := dbq.New(s.Pool)
	rows, err := q.ListUpdateDeviceStates(ctx, dbq.ListUpdateDeviceStatesParams{OrgID: a.Org, UpdateID: update})
	if err != nil {
		return 0, err
	}
	settings := s.settings(ctx, a.Org)
	now := s.now()
	n := 0
	var devices []uuid.UUID
	for _, r := range rows {
		if (hide && (r.State == "missing" || r.State == "downloaded")) || (!hide && r.State == "hidden") {
			job, err := s.Deploy.NewJob(a.Org, r.DeviceID, deploy.JobSpec{Type: agentv1.JobType_JOB_TYPE_WU_HIDE, DBType: "wu_hide",
				Title: hideTitle(hide), NotBefore: now, Expires: now.Add(jobLifetime),
				Body: &agentv1.WuHideBody{Service: settings.service, Updates: []*agentv1.WuUpdateRef{{UpdateId: update.String()}}, Hide: hide}})
			if err != nil {
				return n, err
			}
			if err := q.InsertJob(ctx, job); err != nil {
				return n, err
			}
			devices = append(devices, r.DeviceID)
			n++
		}
	}
	for _, d := range devices {
		s.Deploy.DispatchAsync(d)
	}
	return n, nil
}

func hideTitle(hide bool) string {
	if hide {
		return "Hide Windows update"
	}
	return "Unhide Windows update"
}

type orgWU struct {
	service agentv1.WuService
	drivers bool
	rev     int32
}

// settings reads the organization's Windows Update source settings (defaults when never set).
func (s *Service) settings(ctx context.Context, org uuid.UUID) orgWU {
	out := orgWU{service: agentv1.WuService_WU_SERVICE_DEFAULT, rev: 1}
	os, err := dbq.New(s.Pool).GetOrgSettings(ctx, org)
	if err != nil {
		return out
	}
	switch os.WuService {
	case "windows_update":
		out.service = agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE
	case "microsoft_update":
		out.service = agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE
	}
	out.drivers, out.rev = os.WuIncludeDrivers, os.WuRev
	return out
}

// Settings is the organization's Windows Update source configuration.
type Settings struct {
	Service        string `json:"service"` // default | windows_update | microsoft_update
	IncludeDrivers bool   `json:"include_drivers"`
}

// GetSettings returns the source settings.
func (s *Service) GetSettings(ctx context.Context, org uuid.UUID) Settings {
	out := Settings{Service: "default"}
	if os, err := dbq.New(s.Pool).GetOrgSettings(ctx, org); err == nil {
		out.Service, out.IncludeDrivers = os.WuService, os.WuIncludeDrivers
	}
	return out
}

// SetSettings changes the source settings; every device is then sent a scan job that carries them.
func (s *Service) SetSettings(ctx context.Context, a Actor, in Settings) error {
	switch in.Service {
	case "default", "windows_update", "microsoft_update":
	default:
		return invalid("service must be default, windows_update or microsoft_update")
	}
	now := s.now()
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.BumpWUSettings(ctx, dbq.BumpWUSettingsParams{OrgID: a.Org, WuService: in.Service, WuIncludeDrivers: in.IncludeDrivers}); err != nil {
			return err
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP,
			Action: "settings.update", TargetType: "organization", TargetIDs: []string{a.Org.String()}, Outcome: audit.Success,
			Details: map[string]any{"windows_update_service": in.Service, "include_drivers": in.IncludeDrivers}}, now)
		return err
	})
}

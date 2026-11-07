package updates

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/store"
)

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// ---- auto-approval rules ----

// Rule auto-approves updates that match it, a number of days after their release.
type Rule struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Classifications []string  `json:"classifications"`
	Severities      []string  `json:"severities"`
	IncludeDrivers  bool      `json:"include_drivers"`
	DelayDays       int32     `json:"delay_days"`
	Enabled         bool      `json:"enabled"`
}

var ruleSeverities = map[string]bool{"Critical": true, "Important": true, "Moderate": true, "Low": true, "Unrated": true}

func (r *Rule) normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > 200 {
		return invalid("name must be 1 to 200 characters")
	}
	if len(r.Classifications) > 20 || len(r.Severities) > 5 {
		return invalid("too many classifications or severities")
	}
	for i, c := range r.Classifications {
		r.Classifications[i] = clean(strings.TrimSpace(c), 128)
		if r.Classifications[i] == "" {
			return invalid("empty classification")
		}
	}
	for _, sv := range r.Severities {
		if !ruleSeverities[sv] {
			return invalid("severity must be Critical, Important, Moderate, Low or Unrated")
		}
	}
	if r.DelayDays < 0 || r.DelayDays > 365 {
		return invalid("delay must be between 0 and 365 days")
	}
	if r.Classifications == nil {
		r.Classifications = []string{}
	}
	if r.Severities == nil {
		r.Severities = []string{}
	}
	return nil
}

func ruleView(r dbq.WuRule) Rule {
	return Rule{ID: r.ID, Name: r.Name, Classifications: r.Classifications, Severities: r.Severities, IncludeDrivers: r.IncludeDrivers, DelayDays: r.DelayDays, Enabled: r.Enabled}
}

// ListRules returns the organization's rules.
func (s *Service) ListRules(ctx context.Context, org uuid.UUID) ([]Rule, error) {
	rows, err := dbq.New(s.Pool).ListRules(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(rows))
	for _, r := range rows {
		out = append(out, ruleView(r))
	}
	return out, nil
}

// SaveRule creates (id nil) or replaces a rule.
func (s *Service) SaveRule(ctx context.Context, a Actor, id *uuid.UUID, in Rule) (Rule, error) {
	if err := in.normalize(); err != nil {
		return Rule{}, err
	}
	now := s.now()
	action := "wu.rule_update"
	if id == nil {
		n := uuid.New()
		id, action = &n, "wu.rule_create"
	}
	in.ID = *id
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if action == "wu.rule_create" {
			if err := q.InsertRule(ctx, dbq.InsertRuleParams{ID: in.ID, OrgID: a.Org, Name: in.Name, Classifications: in.Classifications, Severities: in.Severities,
				IncludeDrivers: in.IncludeDrivers, DelayDays: in.DelayDays, Enabled: in.Enabled, CreatedBy: &a.User}); err != nil {
				return err
			}
		} else {
			n, err := q.UpdateRule(ctx, dbq.UpdateRuleParams{ID: in.ID, OrgID: a.Org, Name: in.Name, Classifications: in.Classifications, Severities: in.Severities,
				IncludeDrivers: in.IncludeDrivers, DelayDays: in.DelayDays, Enabled: in.Enabled})
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrNotFound
			}
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: action,
			TargetType: "wu_rule", TargetIDs: []string{in.ID.String()}, Outcome: audit.Success,
			Details: map[string]any{"name": in.Name, "classifications": in.Classifications, "severities": in.Severities, "include_drivers": in.IncludeDrivers,
				"delay_days": in.DelayDays, "enabled": in.Enabled}}, now)
		return err
	})
	if isUnique(err) {
		return Rule{}, ErrConflict
	}
	return in, err
}

// DeleteRule removes a rule. Approvals it already made stay.
func (s *Service) DeleteRule(ctx context.Context, a Actor, id uuid.UUID) error {
	now := s.now()
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.DeleteRule(ctx, dbq.DeleteRuleParams{ID: id, OrgID: a.Org})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "wu.rule_delete",
			TargetType: "wu_rule", TargetIDs: []string{id.String()}, Outcome: audit.Success}, now)
		return err
	})
}

// ---- rings ----

// RebootCfg is a ring's restart policy.
type RebootCfg struct {
	Allow         string `json:"allow"` // never | outside_active_hours | deadline
	ActiveStart   int    `json:"active_start"`
	ActiveEnd     int    `json:"active_end"`
	NotifyMinutes int    `json:"notify_minutes"`
	DeadlineHours int    `json:"deadline_hours"`
}

func (c *RebootCfg) normalize() error {
	switch c.Allow {
	case "", "never":
		*c = RebootCfg{Allow: "never"}
		return nil
	case "outside_active_hours", "deadline":
	default:
		return invalid("restart policy must be never, outside_active_hours or deadline")
	}
	if c.ActiveStart < 0 || c.ActiveStart > 1439 || c.ActiveEnd < 0 || c.ActiveEnd > 1439 {
		return invalid("active hours out of range")
	}
	if c.NotifyMinutes == 0 {
		c.NotifyMinutes = 15
	}
	if c.NotifyMinutes < 1 || c.NotifyMinutes > 1440 {
		return invalid("restart notice must be 1 to 1440 minutes")
	}
	if c.Allow == "deadline" && (c.DeadlineHours < 1 || c.DeadlineHours > 720) {
		return invalid("deadline must be 1 to 720 hours after installation")
	}
	return nil
}

// Proto converts the policy for a job created at now.
func (c RebootCfg) Proto(now time.Time) *agentv1.RebootPolicy {
	p := &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NEVER}
	switch c.Allow {
	case "outside_active_hours":
		p = &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS, NotifyMinutes: uint32(c.NotifyMinutes), // #nosec G115 -- validated
			ActiveHours: &agentv1.ActiveHours{StartMinute: uint32(c.ActiveStart), EndMinute: uint32(c.ActiveEnd)}} // #nosec G115 -- validated
	case "deadline":
		p = &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE, NotifyMinutes: uint32(c.NotifyMinutes), // #nosec G115 -- validated
			DeadlineAt:  now.Add(time.Duration(c.DeadlineHours) * time.Hour).Unix(),
			ActiveHours: &agentv1.ActiveHours{StartMinute: uint32(c.ActiveStart), EndMinute: uint32(c.ActiveEnd)}} // #nosec G115 -- validated
	}
	return p
}

// Ring is a stage of a rollout.
type Ring struct {
	ID               uuid.UUID      `json:"id"`
	Name             string         `json:"name"`
	Ordinal          int32          `json:"ordinal"`
	GroupIDs         []uuid.UUID    `json:"group_ids"`
	DelayDays        int32          `json:"delay_days"`
	SoakHours        int32          `json:"soak_hours"`
	SuccessThreshold int32          `json:"success_threshold"`
	Window           *deploy.Window `json:"window"`
	Reboot           RebootCfg      `json:"restart"`
	Enabled          bool           `json:"enabled"`
}

func ringView(r dbq.WuRing) Ring {
	v := Ring{ID: r.ID, Name: r.Name, Ordinal: r.Ordinal, GroupIDs: r.GroupIds, DelayDays: r.DelayDays, SoakHours: r.SoakHours,
		SuccessThreshold: r.SuccessThreshold, Enabled: r.Enabled}
	if v.GroupIDs == nil {
		v.GroupIDs = []uuid.UUID{}
	}
	if len(r.MaintWindow) > 0 {
		var w deploy.Window
		if json.Unmarshal(r.MaintWindow, &w) == nil {
			v.Window = &w
		}
	}
	_ = json.Unmarshal(r.Reboot, &v.Reboot)
	if v.Reboot.Allow == "" {
		v.Reboot.Allow = "never"
	}
	return v
}

// ListRings returns the rings in order.
func (s *Service) ListRings(ctx context.Context, org uuid.UUID) ([]Ring, error) {
	rows, err := dbq.New(s.Pool).ListRings(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Ring, 0, len(rows))
	for _, r := range rows {
		out = append(out, ringView(r))
	}
	return out, nil
}

// SaveRing creates (id nil) or replaces a ring.
func (s *Service) SaveRing(ctx context.Context, a Actor, id *uuid.UUID, in Ring) (Ring, error) {
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "" || len(in.Name) > 200:
		return Ring{}, invalid("name must be 1 to 200 characters")
	case in.Ordinal < 1 || in.Ordinal > 20:
		return Ring{}, invalid("order must be between 1 and 20")
	case in.DelayDays < 0 || in.DelayDays > 365:
		return Ring{}, invalid("delay must be between 0 and 365 days")
	case in.SoakHours < 0 || in.SoakHours > 2160:
		return Ring{}, invalid("soak time must be between 0 and 2160 hours")
	case in.SuccessThreshold < 1 || in.SuccessThreshold > 100:
		return Ring{}, invalid("success threshold must be between 1 and 100 percent")
	case len(in.GroupIDs) > 20:
		return Ring{}, invalid("too many groups")
	}
	if err := in.Reboot.normalize(); err != nil {
		return Ring{}, err
	}
	if _, err := deploy.WindowProto(in.Window); err != nil {
		return Ring{}, invalid("%s", strings.TrimPrefix(err.Error(), deploy.ErrInvalid.Error()+": "))
	}
	q := dbq.New(s.Pool)
	for _, g := range in.GroupIDs {
		if _, err := q.GetGroup(ctx, dbq.GetGroupParams{ID: g, OrgID: a.Org}); err != nil {
			return Ring{}, invalid("group %s does not exist", g)
		}
	}
	if in.GroupIDs == nil {
		in.GroupIDs = []uuid.UUID{}
	}
	var win []byte
	if in.Window != nil {
		win, _ = json.Marshal(in.Window)
	}
	reboot, _ := json.Marshal(in.Reboot)
	now := s.now()
	action := "wu.ring_update"
	if id == nil {
		n := uuid.New()
		id, action = &n, "wu.ring_create"
	}
	in.ID = *id
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if action == "wu.ring_create" {
			if err := q.InsertRing(ctx, dbq.InsertRingParams{ID: in.ID, OrgID: a.Org, Name: in.Name, Ordinal: in.Ordinal, GroupIds: in.GroupIDs,
				DelayDays: in.DelayDays, SoakHours: in.SoakHours, SuccessThreshold: in.SuccessThreshold, MaintWindow: win, Reboot: reboot, Enabled: in.Enabled}); err != nil {
				return err
			}
		} else {
			n, err := q.UpdateRing(ctx, dbq.UpdateRingParams{ID: in.ID, OrgID: a.Org, Name: in.Name, Ordinal: in.Ordinal, GroupIds: in.GroupIDs,
				DelayDays: in.DelayDays, SoakHours: in.SoakHours, SuccessThreshold: in.SuccessThreshold, MaintWindow: win, Reboot: reboot, Enabled: in.Enabled})
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrNotFound
			}
		}
		_, err := audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: action,
			TargetType: "wu_ring", TargetIDs: []string{in.ID.String()}, Outcome: audit.Success,
			Details: map[string]any{"name": in.Name, "ordinal": in.Ordinal, "groups": len(in.GroupIDs), "delay_days": in.DelayDays, "soak_hours": in.SoakHours,
				"success_threshold": in.SuccessThreshold, "restart": in.Reboot.Allow, "enabled": in.Enabled}}, now)
		return err
	})
	if isUnique(err) {
		return Ring{}, ErrConflict
	}
	s.mu.Lock()
	delete(s.rings, in.ID)
	s.mu.Unlock()
	return in, err
}

// DeleteRing removes a ring (its attempts and holds go with it).
func (s *Service) DeleteRing(ctx context.Context, a Actor, id uuid.UUID) error {
	now := s.now()
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.DeleteRing(ctx, dbq.DeleteRingParams{ID: id, OrgID: a.Org})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "wu.ring_delete",
			TargetType: "wu_ring", TargetIDs: []string{id.String()}, Outcome: audit.Success}, now)
		return err
	})
}

// ---- holds ----

// Hold is an update that failed a ring's success threshold and is kept from later rings.
type Hold struct {
	ID        uuid.UUID `json:"id"`
	UpdateID  uuid.UUID `json:"update_id"`
	Title     string    `json:"title"`
	RingName  string    `json:"ring_name"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// ListHolds returns the open holds.
func (s *Service) ListHolds(ctx context.Context, org uuid.UUID) ([]Hold, error) {
	rows, err := dbq.New(s.Pool).ListHolds(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Hold, 0, len(rows))
	for _, r := range rows {
		title := ""
		if r.Title != nil {
			title = *r.Title
		}
		out = append(out, Hold{ID: r.ID, UpdateID: r.UpdateID, Title: title, RingName: r.RingName, Reason: r.Reason, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

// ReleaseHold lets the update continue to later rings despite the failures. Audited.
func (s *Service) ReleaseHold(ctx context.Context, a Actor, id uuid.UUID) error {
	now := s.now()
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.ReleaseHold(ctx, dbq.ReleaseHoldParams{ID: id, OrgID: a.Org, ReleasedBy: &a.User})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "wu.hold_release",
			TargetType: "wu_hold", TargetIDs: []string{id.String()}, Outcome: audit.Success}, now)
		return err
	})
}

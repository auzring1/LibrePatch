package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/dashboard"
)

// scope says where a caller holds a permission: none, everywhere, or only at some sites.
type scope struct {
	ok    bool
	sites []uuid.UUID // nil = every site
}

func scopeOf(p *Principal, perm string) scope {
	all, ids := p.Access.SitesFor(perm)
	switch {
	case all:
		return scope{ok: true}
	case len(ids) > 0:
		return scope{ok: true, sites: ids}
	}
	return scope{}
}

func (sc scope) has(site uuid.UUID) bool {
	if !sc.ok {
		return false
	}
	if sc.sites == nil {
		return true
	}
	for _, s := range sc.sites {
		if s == site {
			return true
		}
	}
	return false
}

// only narrows a scope to one site (the console's site switcher): nothing is left if the caller has no rights there.
func (sc scope) only(site uuid.UUID) scope {
	if !sc.has(site) {
		return scope{}
	}
	return scope{ok: true, sites: []uuid.UUID{site}}
}

type dashDevices struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Offline int `json:"offline"`
	Pending int `json:"pending"`
}

type dashAttention struct {
	DeviceID uuid.UUID `json:"device_id"`
	Hostname string    `json:"hostname"`
	Reasons  []string  `json:"reasons"` // offline | reboot_pending | critical_missing | failed_updates
	Score    int       `json:"-"`
}

type dashHistoryPoint struct {
	Date         string `json:"date"`
	Compliant    int    `json:"compliant"`
	NonCompliant int    `json:"non_compliant"`
	Unknown      int    `json:"unknown"`
}

type dashTopUpdate struct {
	UpdateID       uuid.UUID `json:"update_id"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	Classification string    `json:"classification"`
	KB             []string  `json:"kb"`
	Devices        int       `json:"devices"`
}

// dashboardView is everything the landing page shows. A section the caller may not see is left out (null), so the
// console hides its widget; site-limited callers get numbers for their sites only.
type dashboardView struct {
	Generated       time.Time          `json:"generated"`
	Devices         *dashDevices       `json:"devices"`
	NeedsRestart    *int               `json:"needs_restart"`
	MissingCritical *int               `json:"missing_critical_devices"`
	FailedJobs24h   *int64             `json:"failed_jobs_24h"`
	Compliance      *dashCompliance    `json:"compliance"`
	TopMissing      []dashTopUpdate    `json:"top_missing"`
	Attention       []dashAttention    `json:"attention"`
	Activity        []auditView        `json:"activity"`
	AgentVersions   []dashAgentVersion `json:"agent_versions"`
	HeldUpdates     *int64             `json:"held_updates"`
}

type dashCompliance struct {
	Compliant    int                `json:"compliant"`
	NonCompliant int                `json:"non_compliant"`
	Unknown      int                `json:"unknown"`
	History      []dashHistoryPoint `json:"history"`
}

type dashAgentVersion struct {
	Version string `json:"version"`
	Devices int    `json:"devices"`
}

const (
	dashHistoryDays = 30
	dashTopN        = 8
	dashAttentionN  = 8
	dashActivityN   = 8
)

// GET /dashboard: the landing page's numbers in one request.
func (s *server) dashboard(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	ctx := r.Context()
	q := s.q()
	now := s.now()
	out := dashboardView{Generated: now, TopMissing: []dashTopUpdate{}, Attention: []dashAttention{}, Activity: []auditView{}, AgentVersions: []dashAgentVersion{}}
	devSc, updSc, jobSc := scopeOf(p, auth.PermDevicesRead), scopeOf(p, auth.PermUpdatesRead), scopeOf(p, auth.PermDeploymentsRead)
	// ?site=<id> narrows every device-based section to one site (the console's site switcher).
	if v := r.URL.Query().Get("site"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			badRequest(w, "site must be a site id")
			return
		}
		devSc, updSc, jobSc = devSc.only(id), updSc.only(id), jobSc.only(id)
	}
	if s.Updates != nil && !s.Updates.On(ctx, p.OrgID) {
		updSc = scope{} // Windows updates are switched off: no compliance, missing-update or hold numbers
	}
	fail := func(what string, err error) bool {
		if err != nil {
			s.Log.Error("dashboard "+what, "err", err)
			internalError(w)
			return true
		}
		return false
	}

	var rows []dbq.ComplianceReportRow
	if devSc.ok || updSc.ok {
		var err error
		if rows, err = q.ComplianceReport(ctx, p.OrgID); fail("compliance", err) {
			return
		}
	}

	if devSc.ok {
		d := dashDevices{}
		counts, err := q.CountDevicesByState(ctx, dbq.CountDevicesByStateParams{OrgID: p.OrgID, SiteIds: devSc.sites})
		if fail("devices", err) {
			return
		}
		d.Online, d.Offline, d.Pending = int(counts.Online), int(counts.Active-counts.Online), int(counts.Pending)
		d.Total = int(counts.Active)
		out.Devices = &d
		restart := 0
		attention := []dashAttention{}
		for _, x := range rows {
			if !devSc.has(x.SiteID) {
				continue
			}
			a := dashAttention{DeviceID: x.ID, Hostname: x.Hostname}
			if !x.Online && (x.LastSeenAt == nil || now.Sub(*x.LastSeenAt) > 24*time.Hour) {
				a.Reasons, a.Score = append(a.Reasons, "offline"), a.Score+2
			}
			if x.RebootPending != nil && *x.RebootPending {
				restart++
				a.Reasons, a.Score = append(a.Reasons, "reboot_pending"), a.Score+1
			}
			if updSc.has(x.SiteID) {
				if x.CriticalMissing > 0 {
					a.Reasons, a.Score = append(a.Reasons, "critical_missing"), a.Score+4
				}
				if x.FailedUpdates > 0 {
					a.Reasons, a.Score = append(a.Reasons, "failed_updates"), a.Score+3
				}
			}
			if len(a.Reasons) > 0 {
				attention = append(attention, a)
			}
		}
		out.NeedsRestart = &restart
		sort.SliceStable(attention, func(i, j int) bool { return attention[i].Score > attention[j].Score })
		if len(attention) > dashAttentionN {
			attention = attention[:dashAttentionN]
		}
		out.Attention = attention
		vs, err := q.AgentVersionCounts(ctx, dbq.AgentVersionCountsParams{OrgID: p.OrgID, SiteIds: devSc.sites})
		if fail("agent versions", err) {
			return
		}
		for _, v := range vs {
			out.AgentVersions = append(out.AgentVersions, dashAgentVersion{Version: v.AgentVersion, Devices: int(v.Devices)})
		}
	}

	if updSc.ok {
		c := dashCompliance{History: []dashHistoryPoint{}}
		crit := 0
		for _, x := range rows {
			if !updSc.has(x.SiteID) {
				continue
			}
			switch complianceState(x, now) {
			case dashboard.Compliant:
				c.Compliant++
			case dashboard.NonCompliant:
				c.NonCompliant++
			default:
				c.Unknown++
			}
			if x.CriticalMissing > 0 {
				crit++
			}
		}
		out.MissingCritical = &crit
		hist, err := q.ListComplianceHistory(ctx, dbq.ListComplianceHistoryParams{OrgID: p.OrgID, Since: dashboard.Date(now.AddDate(0, 0, -dashHistoryDays)), SiteIds: updSc.sites})
		if fail("history", err) {
			return
		}
		for _, h := range hist {
			c.History = append(c.History, dashHistoryPoint{Date: h.TakenOn.Time.Format("2006-01-02"), Compliant: int(h.Compliant), NonCompliant: int(h.NonCompliant), Unknown: int(h.Unknown)})
		}
		out.Compliance = &c
		top, err := q.TopMissingUpdates(ctx, dbq.TopMissingUpdatesParams{OrgID: p.OrgID, SiteIds: updSc.sites, RowLimit: dashTopN})
		if fail("top missing", err) {
			return
		}
		for _, t := range top {
			out.TopMissing = append(out.TopMissing, dashTopUpdate{UpdateID: t.UpdateID, Title: t.Title, Severity: t.Severity, Classification: t.Classification, KB: t.Kb, Devices: int(t.Devices)})
		}
		if p.Access.OrgHas(auth.PermUpdatesRead) {
			n, err := q.OpenHoldCount(ctx, p.OrgID)
			if fail("holds", err) {
				return
			}
			out.HeldUpdates = &n
		}
	}

	if jobSc.ok {
		n, err := q.CountFailedJobsSince(ctx, dbq.CountFailedJobsSinceParams{OrgID: p.OrgID, Since: now.Add(-24 * time.Hour), SiteIds: jobSc.sites})
		if fail("failed jobs", err) {
			return
		}
		out.FailedJobs24h = &n
	}

	if p.Access.OrgHas(auth.PermAuditRead) {
		org := p.OrgID
		lim := int32(dashActivityN)
		al, err := q.ListAudit(ctx, dbq.ListAuditParams{OrgID: &org, Limit: lim})
		if fail("activity", err) {
			return
		}
		names := s.actorNames(r, al)
		for _, a := range al {
			out.Activity = append(out.Activity, auditView{ID: a.ID, TS: a.Ts, ActorType: a.ActorType, ActorID: a.ActorID, ActorName: names[a.ActorID], ActorIP: a.ActorIp,
				Action: a.Action, TargetType: a.TargetType, TargetIDs: a.TargetIds, Outcome: a.Outcome, Details: a.Details})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type notification struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`     // failed_job | held_update | license
	Severity string    `json:"severity"` // info | warning | critical
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	To       string    `json:"to"` // a console path
	At       time.Time `json:"at"`
}

// GET /notifications: things that need a person's attention, drawn from what they may already see. Nothing is stored;
// the list is the current state, so an item disappears once the condition is resolved.
func (s *server) notifications(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	ctx := r.Context()
	q := s.q()
	now := s.now()
	items := []notification{}

	if sc := scopeOf(p, auth.PermDeploymentsRead); sc.ok {
		since := now.Add(-24 * time.Hour)
		total, err := q.CountFailedJobsSince(ctx, dbq.CountFailedJobsSinceParams{OrgID: p.OrgID, Since: since, SiteIds: sc.sites})
		if err != nil {
			internalError(w)
			return
		}
		if total > 0 {
			recent, err := q.ListFailedJobsSince(ctx, dbq.ListFailedJobsSinceParams{OrgID: p.OrgID, Since: since, SiteIds: sc.sites, RowLimit: 5})
			if err != nil {
				internalError(w)
				return
			}
			for _, j := range recent {
				items = append(items, notification{ID: "job-" + j.ID.String(), Kind: "failed_job", Severity: "warning", Title: j.Title + " failed on " + j.Hostname, Detail: j.StatusReason, To: "/devices/" + j.DeviceID.String() + "?tab=jobs", At: j.At})
			}
		}
	}
	if p.Access.OrgHas(auth.PermUpdatesRead) {
		holds, err := q.ListHolds(ctx, p.OrgID)
		if err != nil {
			internalError(w)
			return
		}
		for _, h := range holds {
			title := "An update"
			if h.Title != nil && *h.Title != "" {
				title = *h.Title
			}
			items = append(items, notification{ID: "hold-" + h.ID.String(), Kind: "held_update", Severity: "warning", Title: title + " is held", Detail: h.Reason, To: "/updates/held", At: h.CreatedAt})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].At.After(items[j].At) })
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

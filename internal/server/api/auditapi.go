package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
)

type auditView struct {
	ID         int64           `json:"id"`
	TS         time.Time       `json:"ts"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	ActorIP    string          `json:"actor_ip"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetIDs  []string        `json:"target_ids"`
	Outcome    string          `json:"outcome"`
	Details    json.RawMessage `json:"details"`
}

// auditFilterFrom reads the optional filters shared by the list and the export. Empty values mean "any".
func auditFilterFrom(w http.ResponseWriter, r *http.Request, org uuid.UUID) (dbq.ListAuditParams, bool) {
	q := r.URL.Query()
	p := dbq.ListAuditParams{OrgID: &org}
	str := func(name string, dst **string, max int) bool {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			if len(v) > max {
				badRequest(w, name+" is too long")
				return false
			}
			*dst = &v
		}
		return true
	}
	if !str("action", &p.ActionPrefix, 100) || !str("outcome", &p.Outcome, 20) || !str("actor_type", &p.ActorType, 20) || !str("actor", &p.Actor, 100) || !str("target", &p.Target, 100) {
		return p, false
	}
	if p.ActionPrefix != nil {
		// LIKE wildcards in the prefix are data, not patterns.
		v := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(*p.ActionPrefix)
		p.ActionPrefix = &v
	}
	for name, dst := range map[string]**time.Time{"from": &p.FromTs, "to": &p.ToTs} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				badRequest(w, name+" must be an RFC 3339 time")
				return p, false
			}
			*dst = &t
		}
	}
	return p, true
}

func (s *server) actorNames(r *http.Request, rows []dbq.AuditLog) map[string]string {
	names := map[string]string{}
	for _, a := range rows {
		if a.ActorType != "user" || names[a.ActorID] != "" {
			continue
		}
		if id, err := uuid.Parse(a.ActorID); err == nil {
			if u, err := s.q().GetUserByID(r.Context(), id); err == nil {
				names[a.ActorID] = u.Email
			}
		}
	}
	return names
}

func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	org := principalFrom(r).OrgID
	params, ok := auditFilterFrom(w, r, org)
	if !ok {
		return
	}
	params.Limit = limit
	if v := r.URL.Query().Get("before_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			badRequest(w, "before_id must be a positive integer")
			return
		}
		params.BeforeID = &n
	}
	rows, err := s.q().ListAudit(r.Context(), params)
	if err != nil {
		internalError(w)
		return
	}
	names := s.actorNames(r, rows)
	items := make([]auditView, 0, len(rows))
	for _, a := range rows {
		items = append(items, auditView{ID: a.ID, TS: a.Ts, ActorType: a.ActorType, ActorID: a.ActorID, ActorName: names[a.ActorID], ActorIP: a.ActorIp,
			Action: a.Action, TargetType: a.TargetType, TargetIDs: a.TargetIds, Outcome: a.Outcome, Details: a.Details})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// verifyAudit: POST /audit/verify — walks the whole hash chain. One run at a time.
func (s *server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if !s.verifying.TryLock() {
		writeError(w, http.StatusConflict, "busy", "A verification is already running.")
		return
	}
	defer s.verifying.Unlock()
	start := time.Now()
	res, err := audit.Verify(r.Context(), s.q())
	if err != nil {
		s.Log.Error("verify audit", "err", err)
		internalError(w)
		return
	}
	p := principalFrom(r)
	s.audit(r, p, "audit.verify", "audit_log", nil, map[string]any{"checked": res.Checked, "broken_at": res.BrokenAt})
	writeJSON(w, http.StatusOK, map[string]any{"intact": res.BrokenAt == 0, "checked": res.Checked, "broken_at": res.BrokenAt, "seconds": time.Since(start).Seconds()})
}

const maxAuditExport = 100000

// auditCSV: GET /audit.csv — the filtered log as a spreadsheet-safe CSV (audited like other exports).
func (s *server) auditCSV(w http.ResponseWriter, r *http.Request) {
	org := principalFrom(r).OrgID
	params, ok := auditFilterFrom(w, r, org)
	if !ok {
		return
	}
	cw, ok := s.startCSV(w, r, "audit", map[string]any{"action": r.URL.Query().Get("action"), "from": r.URL.Query().Get("from"), "to": r.URL.Query().Get("to")})
	if !ok {
		return
	}
	_ = csvRow(cw, "id", "time", "action", "outcome", "actor_type", "actor", "actor_ip", "target_type", "targets", "details")
	params.Limit = 1000
	exported := 0
	for exported < maxAuditExport {
		rows, err := s.q().ListAudit(r.Context(), params)
		if err != nil || len(rows) == 0 {
			break
		}
		names := s.actorNames(r, rows)
		for _, a := range rows {
			actor := a.ActorID
			if n := names[a.ActorID]; n != "" {
				actor = n
			}
			if csvRow(cw, strconv.FormatInt(a.ID, 10), a.Ts.UTC().Format(time.RFC3339), a.Action, a.Outcome, a.ActorType, actor, a.ActorIp, a.TargetType, strings.Join(a.TargetIds, " "), string(a.Details)) != nil {
				return
			}
			exported++
		}
		last := rows[len(rows)-1].ID
		params.BeforeID = &last
	}
	cw.Flush()
}

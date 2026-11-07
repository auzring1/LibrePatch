package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/groups"
	"github.com/auzring1/librepatch/internal/server/store"
)

type groupView struct {
	ID          uuid.UUID       `json:"id"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Filter      json.RawMessage `json:"filter"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func viewGroup(g dbq.Group) groupView {
	return groupView{ID: g.ID, Kind: g.Kind, Name: g.Name, Description: g.Description, Filter: g.Filter, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
}

type groupReq struct {
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Filter      json.RawMessage `json:"filter"`
}

// parseFilter validates a filter fully (including SQL compilation) and returns
// its canonical JSON. Anything that does not compile is rejected at save time,
// so stored filters always evaluate.
func parseFilter(raw json.RawMessage) (*groups.Node, []byte, error) {
	n, err := groups.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if _, err := groups.Compile(n, "$1", 2); err != nil {
		return nil, nil, err
	}
	canon, err := json.Marshal(n)
	return n, canon, err
}

func (req *groupReq) validate(w http.ResponseWriter) ([]byte, bool) {
	req.Name = strings.TrimSpace(req.Name)
	if n := utf8.RuneCountInString(req.Name); n < 1 || n > 200 {
		badRequest(w, "name must be 1 to 200 characters")
		return nil, false
	}
	if utf8.RuneCountInString(req.Description) > 1000 {
		badRequest(w, "description must be at most 1000 characters")
		return nil, false
	}
	if strings.ContainsRune(req.Name+req.Description, 0) {
		badRequest(w, "text must not contain NUL")
		return nil, false
	}
	if req.Kind == "static" {
		if len(req.Filter) > 0 && string(req.Filter) != "null" {
			badRequest(w, "a static group has no filter")
			return nil, false
		}
		return nil, true
	}
	_, canon, err := parseFilter(req.Filter)
	if err != nil {
		writeFilterError(w, err)
		return nil, false
	}
	return canon, true
}

func kindOf(k string) string {
	if k == "static" {
		return "static"
	}
	return "dynamic"
}

func writeFilterError(w http.ResponseWriter, err error) {
	if errors.Is(err, groups.ErrInvalid) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_filter", strings.TrimPrefix(err.Error(), groups.ErrInvalid.Error()+": "))
		return
	}
	badRequest(w, "malformed filter")
}

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (s *server) listGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := s.q().ListGroups(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		internalError(w)
		return
	}
	items := make([]groupView, 0, len(rows))
	for _, g := range rows {
		items = append(items, viewGroup(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) groupFromURL(w http.ResponseWriter, r *http.Request) (dbq.Group, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Group not found.")
		return dbq.Group{}, false
	}
	g, err := s.q().GetGroup(r.Context(), dbq.GetGroupParams{ID: id, OrgID: principalFrom(r).OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not_found", "Group not found.")
		return dbq.Group{}, false
	} else if err != nil {
		internalError(w)
		return dbq.Group{}, false
	}
	return g, true
}

func (s *server) getGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromURL(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, viewGroup(g))
}

func (s *server) createGroup(w http.ResponseWriter, r *http.Request) {
	var req groupReq
	if !decode(w, r, &req) {
		return
	}
	filter, ok := req.validate(w)
	if !ok {
		return
	}
	p, id, now := principalFrom(r), uuid.New(), s.now()
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if err := q.CreateGroup(r.Context(), dbq.CreateGroupParams{ID: id, OrgID: p.OrgID, Name: req.Name,
			Description: req.Description, Kind: kindOf(req.Kind), Filter: filter, CreatedBy: p.UserID}); err != nil {
			return err
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "group.create", TargetType: "group", TargetIDs: []string{id.String()},
			Outcome: audit.Success, Details: map[string]any{"name": req.Name}}, now)
		return err
	})
	if isUnique(err) {
		writeError(w, http.StatusConflict, "name_taken", "A group with that name already exists.")
		return
	} else if err != nil {
		s.Log.Error("create group", "err", err)
		internalError(w)
		return
	}
	g, ok := s.groupByID(w, r, id)
	if ok {
		writeJSON(w, http.StatusCreated, viewGroup(g))
	}
}

func (s *server) groupByID(w http.ResponseWriter, r *http.Request, id uuid.UUID) (dbq.Group, bool) {
	g, err := s.q().GetGroup(r.Context(), dbq.GetGroupParams{ID: id, OrgID: principalFrom(r).OrgID})
	if err != nil {
		internalError(w)
		return dbq.Group{}, false
	}
	return g, true
}

func (s *server) updateGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromURL(w, r)
	if !ok {
		return
	}
	var req groupReq
	if !decode(w, r, &req) {
		return
	}
	req.Kind = g.Kind // the kind of a group never changes
	filter, ok := req.validate(w)
	if !ok {
		return
	}
	p, now := principalFrom(r), s.now()
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		n, err := q.UpdateGroup(r.Context(), dbq.UpdateGroupParams{ID: g.ID, OrgID: p.OrgID, Name: req.Name,
			Description: req.Description, Filter: filter, UpdatedAt: now})
		if err != nil {
			return err
		}
		if n == 0 {
			return errConflict
		}
		_, err = audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "group.update", TargetType: "group", TargetIDs: []string{g.ID.String()},
			Outcome: audit.Success, Details: map[string]any{"name": req.Name}}, now)
		return err
	})
	switch {
	case isUnique(err):
		writeError(w, http.StatusConflict, "name_taken", "A group with that name already exists.")
	case errors.Is(err, errConflict):
		writeError(w, http.StatusNotFound, "not_found", "Group not found.")
	case err != nil:
		s.Log.Error("update group", "err", err)
		internalError(w)
	default:
		if g, ok := s.groupByID(w, r, g.ID); ok {
			writeJSON(w, http.StatusOK, viewGroup(g))
		}
	}
}

func (s *server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromURL(w, r)
	if !ok {
		return
	}
	p, now := principalFrom(r), s.now()
	err := store.Tx(r.Context(), s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if _, err := q.DeleteGroup(r.Context(), dbq.DeleteGroupParams{ID: g.ID, OrgID: p.OrgID}); err != nil {
			return err
		}
		_, err := audit.Write(r.Context(), tx, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
			ActorIP: clientIP(r), Action: "group.delete", TargetType: "group", TargetIDs: []string{g.ID.String()},
			Outcome: audit.Success, Details: map[string]any{"name": g.Name}}, now)
		return err
	})
	if err != nil {
		s.Log.Error("delete group", "err", err)
		internalError(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) evaluate(w http.ResponseWriter, r *http.Request, f *groups.Node) {
	limit, offset, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	members, total, err := groups.Evaluate(r.Context(), s.Pool, principalFrom(r).OrgID, f, limit, offset)
	if errors.Is(err, groups.ErrInvalid) {
		writeFilterError(w, err)
		return
	} else if err != nil {
		s.Log.Error("evaluate group filter", "err", err)
		writeError(w, http.StatusServiceUnavailable, "evaluation_failed", "The filter could not be evaluated (it may be too expensive). Narrow it and retry.")
		return
	}
	if members == nil {
		members = []groups.Member{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": members, "total": total})
}

// groupDevices: GET /groups/{id}/devices — current members of a dynamic group.
func (s *server) groupDevices(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromURL(w, r)
	if !ok {
		return
	}
	if g.Kind == "static" {
		s.staticMembers(w, r, g)
		return
	}
	f, err := groups.Parse(g.Filter)
	if err != nil {
		writeFilterError(w, err)
		return
	}
	s.evaluate(w, r, f)
}

func (s *server) staticMembers(w http.ResponseWriter, r *http.Request, g dbq.Group) {
	limit, offset, ok := paging(w, r, 100, 500)
	if !ok {
		return
	}
	q := s.q()
	rows, err := q.ListGroupMembers(r.Context(), dbq.ListGroupMembersParams{GroupID: g.ID, OrgID: g.OrgID, Limit: limit, Offset: offset})
	if err != nil {
		internalError(w)
		return
	}
	total, _ := q.CountGroupMembers(r.Context(), dbq.CountGroupMembersParams{GroupID: g.ID, OrgID: g.OrgID})
	items := make([]groups.Member, 0, len(rows))
	for _, d := range rows {
		items = append(items, groups.Member{ID: d.ID, Hostname: d.Hostname, Chassis: d.Chassis, Manufacturer: d.Manufacturer, Model: d.Model,
			OSCaption: d.OsCaption, Online: d.Online, LastSeenAt: d.LastSeenAt, SoftwareCount: d.SoftwareCount})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// changeGroupMembers: POST /groups/{id}/members {add:[ids], remove:[ids]} (static groups only).
func (s *server) changeGroupMembers(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupFromURL(w, r)
	if !ok {
		return
	}
	if g.Kind != "static" {
		writeError(w, http.StatusConflict, "not_static", "Only static groups have an explicit member list.")
		return
	}
	var req struct {
		Add    []uuid.UUID `json:"add"`
		Remove []uuid.UUID `json:"remove"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Add) > 5000 || len(req.Remove) > 5000 {
		badRequest(w, "at most 5000 devices per request")
		return
	}
	p := principalFrom(r)
	q := s.q()
	if len(req.Add) > 0 {
		if err := q.AddGroupMembers(r.Context(), dbq.AddGroupMembersParams{GroupID: g.ID, AddedBy: p.UserID, OrgID: p.OrgID, DeviceIds: req.Add}); err != nil {
			internalError(w)
			return
		}
	}
	if len(req.Remove) > 0 {
		if err := q.RemoveGroupMembers(r.Context(), dbq.RemoveGroupMembersParams{GroupID: g.ID, OrgID: p.OrgID, DeviceIds: req.Remove}); err != nil {
			internalError(w)
			return
		}
	}
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: "group.members", TargetType: "group", TargetIDs: []string{g.ID.String()}, Outcome: audit.Success,
		Details: map[string]any{"name": g.Name, "added": len(req.Add), "removed": len(req.Remove)}})
	w.WriteHeader(http.StatusNoContent)
}

// previewGroup: POST /groups/preview — evaluate an unsaved filter.
func (s *server) previewGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filter json.RawMessage `json:"filter"`
	}
	if !decode(w, r, &req) {
		return
	}
	f, _, err := parseFilter(req.Filter)
	if err != nil {
		writeFilterError(w, err)
		return
	}
	s.evaluate(w, r, f)
}

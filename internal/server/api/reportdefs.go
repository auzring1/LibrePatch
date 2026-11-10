package api

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/server/groups"
	"github.com/auzring1/librepatch/internal/server/pdf"
	"github.com/auzring1/librepatch/internal/server/reportbuilder"
	"github.com/auzring1/librepatch/internal/shared/brand"
)

// previewRows is how many rows the console shows before a person exports.
const previewRows = 1000

// exportRows bounds one report export (CSV and PDF).
const exportRows = 200_000

func (s *server) reportStore() *reportbuilder.Store { return &reportbuilder.Store{Pool: s.Pool} }

// reportsWU reports whether the organization manages Windows updates, which patch data needs.
func (s *server) reportsWU(r *http.Request) bool {
	return s.Updates != nil && s.Updates.On(r.Context(), principalFrom(r).OrgID)
}

type columnView struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Kind    string   `json:"kind"`
	Group   string   `json:"group"`
	Choices []string `json:"choices,omitempty"`
	Ops     []string `json:"ops"`
}

type datasetView struct {
	ID             string       `json:"id"`
	Label          string       `json:"label"`
	Description    string       `json:"description"`
	DefaultColumns []string     `json:"default_columns"`
	Columns        []columnView `json:"columns"`
}

// reportCatalog: GET /reports/catalog — the data a report can read, the ready-made reports and the saved ones.
func (s *server) reportCatalog(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	wu := s.reportsWU(r)
	out := struct {
		Datasets []datasetView           `json:"datasets"`
		Builtins []reportbuilder.Builtin `json:"builtins"`
		Saved    []reportbuilder.Saved   `json:"saved"`
	}{Datasets: []datasetView{}, Builtins: []reportbuilder.Builtin{}}
	off := map[string]bool{}
	for _, d := range reportbuilder.Datasets() {
		if d.NeedsWindowsUpdates && !wu {
			off[d.ID] = true
			continue
		}
		v := datasetView{ID: d.ID, Label: d.Label, Description: d.Description, DefaultColumns: d.DefaultColumns}
		for _, c := range d.Columns {
			v.Columns = append(v.Columns, columnView{ID: c.ID, Label: c.Label, Kind: string(c.Kind), Group: c.Group, Choices: c.Choices, Ops: reportbuilder.Ops(c.Kind)})
		}
		out.Datasets = append(out.Datasets, v)
	}
	for _, b := range reportbuilder.Builtins() {
		if !off[b.Spec.Dataset] {
			out.Builtins = append(out.Builtins, b)
		}
	}
	saved, err := s.reportStore().List(r.Context(), p.OrgID)
	if err != nil {
		s.Log.Error("list saved reports", "err", err)
		internalError(w)
		return
	}
	for _, x := range saved {
		if !off[x.Spec.Dataset] {
			out.Saved = append(out.Saved, x)
		}
	}
	if out.Saved == nil {
		out.Saved = []reportbuilder.Saved{}
	}
	writeJSON(w, http.StatusOK, out)
}

// groupFor loads the group a spec is limited to, or reports why it cannot.
func (s *server) groupFor(w http.ResponseWriter, r *http.Request, sp reportbuilder.Spec) (*groups.Node, bool) {
	if sp.GroupID == nil {
		return nil, true
	}
	g, err := s.q().GetGroup(r.Context(), dbq.GetGroupParams{ID: *sp.GroupID, OrgID: principalFrom(r).OrgID})
	if err != nil {
		badRequest(w, "The group chosen for this report no longer exists.")
		return nil, false
	}
	n, err := groups.Parse(g.Filter)
	if err != nil {
		writeFilterError(w, err)
		return nil, false
	}
	return n, true
}

type runBody struct {
	Spec   reportbuilder.Spec `json:"spec"`
	Format string             `json:"format"`
	Title  string             `json:"title"`
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func fileStem(title string) string {
	t := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(title), "-"), "-")
	if t == "" {
		t = "report"
	}
	if len(t) > 60 {
		t = strings.Trim(t[:60], "-")
	}
	return t
}

// runReport: POST /reports/run — {spec, format: json|csv|pdf, title}. The preview (json) needs reports:read; a file
// needs inventory:export and is audited, like every other export.
func (s *server) runReport(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	var b runBody
	if !decode(w, r, &b) {
		return
	}
	if b.Format == "" {
		b.Format = "json"
	}
	if b.Format != "json" && b.Format != "csv" && b.Format != "pdf" {
		badRequest(w, "format must be json, csv or pdf.")
		return
	}
	if b.Format != "json" && !p.Access.OrgHas(auth.PermInventoryExport) {
		writeError(w, http.StatusForbidden, "forbidden", "You may not export reports.")
		return
	}
	title := strings.TrimSpace(b.Title)
	if utf8.RuneCountInString(title) > 120 {
		badRequest(w, "The title is too long.")
		return
	}
	sp, ds, err := b.Spec.Validate(s.reportsWU(r))
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	if title == "" {
		title = ds.Label
	}
	grp, ok := s.groupFor(w, r, sp)
	if !ok {
		return
	}
	limit := previewRows
	if b.Format != "json" {
		limit = exportRows
	}
	res, err := reportbuilder.Run(r.Context(), s.Pool, p.OrgID, sp, grp, s.reportsWU(r), limit)
	if err != nil {
		if reportbuilder.IsSpecError(err) {
			badRequest(w, err.Error())
			return
		}
		s.Log.Error("run report", "dataset", sp.Dataset, "err", err)
		internalError(w)
		return
	}
	if b.Format == "json" {
		writeJSON(w, http.StatusOK, res)
		return
	}
	if err := audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
		ActorIP: clientIP(r), Action: "inventory.export", TargetType: "report", TargetIDs: []string{"custom-" + sp.Dataset},
		Outcome: audit.Success, Details: map[string]any{"kind": "custom-" + sp.Dataset, "title": title, "format": b.Format, "rows": res.Total,
			"columns": len(sp.Columns), "filters": len(sp.Filters), "sites": len(sp.SiteIDs), "group": sp.GroupID != nil}}); err != nil {
		s.Log.Error("audit export", "err", err)
		internalError(w)
		return
	}
	stamp := s.now().UTC().Format("20060102-150405")
	name := brand.Slug + "-" + fileStem(title) + "-" + stamp
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if b.Format == "csv" {
		data, err := reportbuilder.CSV(res)
		if err != nil {
			internalError(w)
			return
		}
		h.Set("Content-Type", "text/csv; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		_, _ = w.Write(data)
		return
	}
	doc := pdf.Doc{ProductName: brand.Name, Title: title, Footer: brand.Name, Accent: pdf.ParseHexColor(brandingDefaultsForReport().Accent), Generated: s.now()}
	if s.Branding != nil {
		if rb, err := s.Branding.ForReport(r.Context(), p.OrgID); err == nil {
			doc.OrgName, doc.ProductName, doc.Accent, doc.LogoPNG = rb.OrgName, rb.ProductName, pdf.ParseHexColor(rb.AccentColor), rb.LogoPNG
			doc.Footer = strings.TrimSpace(rb.OrgName + " " + rb.ProductName)
			if rb.Footer != "" {
				doc.Footer = rb.Footer
			}
		}
	}
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Disposition", `attachment; filename="`+name+`.pdf"`)
	_, _ = w.Write(reportbuilder.PDF(doc, res))
}

type savedBody struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Spec        reportbuilder.Spec `json:"spec"`
}

func (s *server) checkSavedBody(w http.ResponseWriter, r *http.Request) (savedBody, bool) {
	var b savedBody
	if !decode(w, r, &b) {
		return b, false
	}
	b.Name, b.Description = strings.TrimSpace(b.Name), strings.TrimSpace(b.Description)
	if n := utf8.RuneCountInString(b.Name); n < 1 || n > 120 {
		badRequest(w, "Give the report a name of up to 120 characters.")
		return b, false
	}
	if utf8.RuneCountInString(b.Description) > 500 {
		badRequest(w, "The description may have at most 500 characters.")
		return b, false
	}
	sp, _, err := b.Spec.Validate(s.reportsWU(r))
	if err != nil {
		badRequest(w, err.Error())
		return b, false
	}
	b.Spec = sp
	if _, ok := s.groupFor(w, r, sp); !ok {
		return b, false
	}
	return b, true
}

func (s *server) savedError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, reportbuilder.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Report not found.")
	case errors.Is(err, reportbuilder.ErrNameTaken):
		writeError(w, http.StatusConflict, "name_taken", "Another report already has this name.")
	default:
		s.Log.Error("saved report", "err", err)
		internalError(w)
	}
}

// createSavedReport: POST /reports/saved
func (s *server) createSavedReport(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	b, ok := s.checkSavedBody(w, r)
	if !ok {
		return
	}
	sv, err := s.reportStore().Create(r.Context(), p.OrgID, &p.UserID, b.Name, b.Description, b.Spec)
	if err != nil {
		s.savedError(w, err)
		return
	}
	s.audit(r, p, "report.create", "report", []string{sv.ID.String()}, map[string]any{"name": sv.Name, "dataset": sv.Spec.Dataset})
	writeJSON(w, http.StatusCreated, sv)
}

// updateSavedReport: PUT /reports/saved/{id}
func (s *server) updateSavedReport(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		badRequest(w, "The report id is not valid.")
		return
	}
	b, ok := s.checkSavedBody(w, r)
	if !ok {
		return
	}
	sv, err := s.reportStore().Update(r.Context(), p.OrgID, id, b.Name, b.Description, b.Spec)
	if err != nil {
		s.savedError(w, err)
		return
	}
	s.audit(r, p, "report.update", "report", []string{sv.ID.String()}, map[string]any{"name": sv.Name, "dataset": sv.Spec.Dataset})
	writeJSON(w, http.StatusOK, sv)
}

// deleteSavedReport: DELETE /reports/saved/{id}
func (s *server) deleteSavedReport(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		badRequest(w, "The report id is not valid.")
		return
	}
	old, err := s.reportStore().Get(r.Context(), p.OrgID, id)
	if err != nil {
		s.savedError(w, err)
		return
	}
	if err := s.reportStore().Delete(r.Context(), p.OrgID, id); err != nil {
		s.savedError(w, err)
		return
	}
	s.audit(r, p, "report.delete", "report", []string{id.String()}, map[string]any{"name": old.Name})
	w.WriteHeader(http.StatusNoContent)
}

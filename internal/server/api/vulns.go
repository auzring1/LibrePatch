package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/vulns"
)

func (s *server) vulnSvc(w http.ResponseWriter) bool {
	if s.Vulns == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Vulnerability lookup is not available.")
		return false
	}
	return true
}

func (s *server) vulnError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vulns.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", strings.TrimPrefix(err.Error(), vulns.ErrInvalid.Error()+": "))
	case errors.Is(err, vulns.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.Is(err, vulns.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", strings.TrimPrefix(err.Error(), vulns.ErrConflict.Error()+": "))
	case errors.Is(err, vulns.ErrOff):
		writeError(w, http.StatusConflict, "lookup_off", "Turn on \"Look up known vulnerabilities\" under Settings > Vulnerability data first.")
	default:
		s.Log.Error("vulnerabilities", "err", err)
		internalError(w)
	}
}

func (s *server) vulnAudit(r *http.Request, action, target string, details map[string]any) {
	p := principalFrom(r)
	_ = audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(), ActorIP: clientIP(r),
		Action: action, TargetType: "vulnerabilities", TargetIDs: []string{target}, Outcome: audit.Success, Details: details})
}

func vulnFilter(r *http.Request) vulns.Filter {
	q := r.URL.Query()
	f := vulns.Filter{Exploited: q.Get("exploited") == "true", Query: q.Get("q")}
	for _, sv := range strings.Split(q.Get("severity"), ",") {
		switch sv = strings.ToLower(strings.TrimSpace(sv)); sv {
		case "low", "medium", "high", "critical":
			f.Severity = append(f.Severity, sv)
		}
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil {
		f.Limit = n
	}
	return f
}

// GET /vulnerabilities: the CVEs that affect the fleet, with a summary and the state of the data.
func (s *server) listVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	org := principalFrom(r).OrgID
	items, sum, err := s.Vulns.Store.Overview(r.Context(), org, vulnFilter(r))
	if err != nil {
		s.vulnError(w, err)
		return
	}
	st, err := s.Vulns.Status(r.Context(), org)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": sum, "items": items, "status": st})
}

// GET /vulnerabilities/{cve}/devices
func (s *server) vulnerabilityDevices(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	id := strings.ToUpper(chi.URLParam(r, "cve"))
	if !strings.HasPrefix(id, "CVE-") || len(id) > 40 {
		badRequest(w, "that is not a CVE id")
		return
	}
	hits, err := s.Vulns.Store.DevicesFor(r.Context(), principalFrom(r).OrgID, id)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": hits})
}

// GET /devices/{id}/vulnerabilities
func (s *server) deviceVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	d, ok := s.deviceFromURL(w, r)
	if !ok {
		return
	}
	items, err := s.Vulns.Store.ForDevice(r.Context(), d.OrgID, d.ID)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	st, err := s.Vulns.Status(r.Context(), d.OrgID)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "enabled": st.Enabled, "has_data": st.Counts.CVEs > 0})
}

// GET /vulnerabilities.csv
func (s *server) vulnerabilitiesCSV(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	f := vulnFilter(r)
	f.Limit = 2000
	items, _, err := s.Vulns.Store.Overview(r.Context(), principalFrom(r).OrgID, f)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	cw, ok := s.startCSV(w, r, "vulnerabilities", map[string]any{"exploited": f.Exploited, "severity": f.Severity, "q": f.Query})
	if !ok {
		return
	}
	_ = csvRow(cw, "cve", "severity", "cvss", "known_exploited", "ransomware_use", "fix_due", "devices", "affected_software", "fixed_in", "published", "summary")
	day := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02")
	}
	for _, it := range items {
		score := ""
		if it.CVSS != nil {
			score = strconv.FormatFloat(float64(*it.CVSS), 'f', 1, 32)
		}
		if csvRow(cw, it.ID, it.Severity, score, strconv.FormatBool(it.Exploited), strconv.FormatBool(it.Ransomware), day(it.KEVDue), strconv.Itoa(it.Devices),
			strings.Join(it.Products, "; "), strings.Join(it.FixedIn, "; "), day(it.Published), it.Summary) != nil {
			return
		}
	}
	cw.Flush()
}

// POST /vulnerabilities/sync: download the feeds now.
func (s *server) syncVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	rep, err := s.Vulns.Sync(r.Context(), principalFrom(r).OrgID, true)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	s.vulnAudit(r, "vulns.sync", "feeds", map[string]any{"kev": rep.KEV, "products": rep.Products, "cves": rep.CVEs, "requests": rep.Requests, "errors": len(rep.Errors)})
	writeJSON(w, http.StatusOK, rep)
}

// POST /vulnerabilities/import: load a feed file by hand.
func (s *server) importVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	var in struct {
		Kind string `json:"kind"`
		Data string `json:"data"`
	}
	if !decode(w, r, &in) {
		return
	}
	res, err := s.Vulns.Import(r.Context(), in.Kind, []byte(in.Data))
	if err != nil {
		s.vulnError(w, err)
		return
	}
	s.vulnAudit(r, "vulns.import", in.Kind, map[string]any{"kind": in.Kind, "items": res.Items})
	writeJSON(w, http.StatusOK, res)
}

// GET /vulnerabilities/products: which installed programs are looked up, and as what.
func (s *server) listVulnProducts(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	org := principalFrom(r).OrgID
	_ = s.Vulns.Store.EnsureBuiltinProducts(r.Context(), org)
	items, err := s.Vulns.Store.ListProducts(r.Context(), org)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// POST /vulnerabilities/products
func (s *server) addVulnProduct(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	var in struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor"`
		Product string `json:"product"`
	}
	if !decode(w, r, &in) {
		return
	}
	p, err := s.Vulns.Store.AddProduct(r.Context(), principalFrom(r).OrgID, in.Name, in.Vendor, in.Product)
	if err != nil {
		s.vulnError(w, err)
		return
	}
	s.vulnAudit(r, "vulns.product_add", p.ID.String(), map[string]any{"name": p.Name, "vendor": p.Vendor, "product": p.Product})
	writeJSON(w, http.StatusCreated, p)
}

// PUT /vulnerabilities/products/{id}
func (s *server) setVulnProduct(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.Vulns.Store.SetProductEnabled(r.Context(), principalFrom(r).OrgID, id, in.Enabled); err != nil {
		s.vulnError(w, err)
		return
	}
	s.vulnAudit(r, "vulns.product_update", id.String(), map[string]any{"enabled": in.Enabled})
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /vulnerabilities/products/{id}
func (s *server) deleteVulnProduct(w http.ResponseWriter, r *http.Request) {
	if !s.vulnSvc(w) {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.Vulns.Store.DeleteProduct(r.Context(), principalFrom(r).OrgID, id); err != nil {
		s.vulnError(w, err)
		return
	}
	s.vulnAudit(r, "vulns.product_delete", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

package api

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"time"

	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/shared/brand"
)

// The printable report is a standalone page: no scripts, one nonce-protected style block, and the logo inlined as a
// data: image, so it can be saved, emailed or printed to PDF and still look right. html/template escapes every value.
var complianceTmpl = template.Must(template.New("compliance").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
:root{--accent:{{.Accent}}}
*{box-sizing:border-box}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1a1b1e;background:#fff;margin:2rem auto;max-width:1100px;padding:0 1rem}
header{display:flex;align-items:center;gap:1rem;border-bottom:3px solid var(--accent);padding-bottom:.75rem;margin-bottom:1rem}
header img{max-height:64px;max-width:260px;object-fit:contain}
h1{font-size:1.4rem;margin:0;color:var(--accent)}
.org{font-size:1.05rem;font-weight:600}
.meta{color:#495057;font-size:.85rem}
.summary{display:flex;gap:1.5rem;margin:1rem 0;flex-wrap:wrap}
.summary div{border:1px solid #ced4da;border-radius:6px;padding:.5rem .9rem}
.summary b{display:block;font-size:1.4rem}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border-bottom:1px solid #dee2e6;padding:.35rem .5rem;text-align:left;vertical-align:top}
th{border-bottom:2px solid var(--accent)}
td.n{text-align:right}
footer{margin-top:2rem;padding-top:.75rem;border-top:1px solid #ced4da;color:#495057;font-size:.8rem;white-space:pre-line}
@media print{body{margin:0;max-width:none}tr{break-inside:avoid}}
</style></head><body>
<header>
{{if .Logo}}<img src="{{.Logo}}" alt="{{if .Org}}{{.Org}} logo{{else}}Logo{{end}}">{{end}}
<div>{{if .Org}}<div class="org">{{.Org}}</div>{{end}}<h1>Patch compliance report</h1>
<div class="meta">Generated {{.Generated}} by {{.Product}}</div></div>
</header>
<div class="summary">
<div><b>{{.Total}}</b>Devices</div>
<div><b>{{.Compliant}}</b>Compliant</div>
<div><b>{{.NonCompliant}}</b>Not compliant</div>
<div><b>{{.Unknown}}</b>Unknown</div>
</div>
<table>
<thead><tr><th>Device</th><th>State</th><th class="n">Approved missing</th><th class="n">Critical missing</th><th class="n">Failed</th><th>Restart pending</th><th>Last scan</th><th>Operating system</th></tr></thead>
<tbody>
{{range .Rows}}<tr><td>{{.Hostname}}</td><td>{{.State}}</td><td class="n">{{.ApprovedMissing}}</td><td class="n">{{.CriticalMissing}}</td><td class="n">{{.FailedUpdates}}</td><td>{{if .RebootPending}}Yes{{else}}No{{end}}</td><td>{{.LastScan}}</td><td>{{.OS}}</td></tr>
{{else}}<tr><td colspan="8">No devices.</td></tr>
{{end}}</tbody></table>
{{if .Footer}}<footer>{{.Footer}}</footer>{{end}}
</body></html>
`))

type complianceView struct {
	Title, Org, Product, Footer, Accent, Nonce, Generated string
	Logo                                                  template.URL // built from the server's own PNG bytes
	Total, Compliant, NonCompliant, Unknown               int
	Rows                                                  []complianceHTMLRow
}

type complianceHTMLRow struct {
	Hostname, State, OS, LastScan                   string
	ApprovedMissing, CriticalMissing, FailedUpdates int32
	RebootPending                                   bool
}

var stateLabels = map[string]string{"compliant": "Compliant", "non_compliant": "Not compliant", "unknown": "Unknown"}

// complianceHTML: GET /reports/compliance.html — the compliance report as a printable page that carries the
// deployment's report logo, organization name and footer text.
func (s *server) complianceHTML(w http.ResponseWriter, r *http.Request) {
	if !s.windowsUpdates(w, r) {
		return
	}
	p := principalFrom(r)
	rows, err := s.complianceRows(r)
	if err != nil {
		internalError(w)
		return
	}
	rb := brandingDefaultsForReport()
	if s.Branding != nil {
		if b, err := s.Branding.ForReport(r.Context(), p.OrgID); err == nil {
			rb.Product, rb.Org, rb.Footer, rb.Accent, rb.Logo = b.ProductName, b.OrgName, b.Footer, b.AccentColor, template.URL(b.LogoDataURI) // #nosec G203 -- data: URI assembled from the re-encoded PNG
		}
	}
	title := "Patch compliance report · " + rb.Product
	if rb.Org != "" {
		title = "Patch compliance report · " + rb.Org
	}
	nb := make([]byte, 18)
	_, _ = rand.Read(nb)
	nonce := base64.StdEncoding.EncodeToString(nb)
	now := s.now()
	v := complianceView{Title: title, Org: rb.Org, Product: rb.Product, Footer: rb.Footer, Accent: rb.Accent, Nonce: nonce,
		Generated: now.UTC().Format("2006-01-02 15:04 UTC"), Logo: rb.Logo, Total: len(rows)}
	ts := func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return t.UTC().Format("2006-01-02")
	}
	for _, x := range rows {
		switch x.State {
		case "compliant":
			v.Compliant++
		case "non_compliant":
			v.NonCompliant++
		default:
			v.Unknown++
		}
		v.Rows = append(v.Rows, complianceHTMLRow{Hostname: x.Hostname, State: stateLabels[x.State], OS: x.OS, LastScan: ts(x.LastScanAt),
			ApprovedMissing: x.ApprovedMissing, CriticalMissing: x.CriticalMissing, FailedUpdates: x.FailedUpdates, RebootPending: x.RebootPending})
	}
	if err := audit.Log(r.Context(), s.Pool, audit.Entry{OrgID: &p.OrgID, ActorType: audit.ActorUser, ActorID: p.UserID.String(),
		ActorIP: clientIP(r), Action: "inventory.export", TargetType: "report", TargetIDs: []string{"compliance-html"},
		Outcome: audit.Success, Details: map[string]any{"kind": "compliance-html"}}); err != nil {
		s.Log.Error("audit export", "err", err)
		internalError(w)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Disposition", `inline; filename="`+brand.Slug+`-compliance-`+now.UTC().Format("20060102-150405")+`.html"`)
	if err := complianceTmpl.Execute(w, v); err != nil {
		s.Log.Error("render report", "err", err)
	}
}

type reportBrand struct {
	Product, Org, Footer, Accent string
	Logo                         template.URL
}

// brandingDefaultsForReport is what a report shows when branding is unavailable.
func brandingDefaultsForReport() reportBrand {
	return reportBrand{Product: brand.Name, Accent: branding.DefaultAccent}
}

// Package webui serves the embedded single-page console with a strict,
// per-request-nonce Content-Security-Policy.
package webui

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"html"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/auzring1/librepatch/internal/shared/brand"
)

//go:embed all:dist
var dist embed.FS

const (
	noncePlaceholder = "__CSP_NONCE__"
	headPlaceholder  = "<!--BRAND_HEAD-->"
)

// Head is the per-deployment branding injected into the index shell so the
// first paint already carries the right title, favicon and colours.
type Head struct {
	Title   string // plain text; escaped here
	Favicon string // same-origin URL
	JSON    string // already-marshalled public branding, embedded as inert data
}

// HeadFunc resolves the Head for a request. It must not fail: on any error
// return the zero value and the product defaults are used.
type HeadFunc func(ctx context.Context) Head

// Handler serves static assets and falls back to index.html for SPA routes.
func Handler(head HeadFunc) http.Handler {
	sub, _ := fs.Sub(dist, "dist")
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		index = []byte(`<!doctype html><html><head><meta charset="utf-8">` + headPlaceholder + `</head>` +
			`<body><p>The web console was not built into this binary. Run <code>make web</code> and rebuild.</p></body></html>`)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if strings.HasPrefix(p, "/api/") {
			http.NotFound(w, r)
			return
		}
		if p != "/" && p != "/index.html" {
			if f, err := sub.Open(strings.TrimPrefix(p, "/")); err == nil {
				st, _ := f.Stat()
				_ = f.Close()
				if st != nil && !st.IsDir() {
					if strings.HasPrefix(p, "/assets/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
					files.ServeHTTP(w, r)
					return
				}
			}
		}
		var h Head
		if head != nil {
			h = head(r.Context())
		}
		serveIndex(w, index, h)
	})
}

// renderHead builds the <title>, favicon and branding-data tags. The JSON
// block is type application/json, so it is data, never executed (and the CSP
// allows no inline scripts anyway); "<" is escaped so it cannot close the tag.
func renderHead(h Head) string {
	title := h.Title
	if title == "" {
		title = brand.Name
	}
	icon := h.Favicon
	if icon == "" || !strings.HasPrefix(icon, "/") || strings.HasPrefix(icon, "//") {
		icon = "/favicon.svg"
	}
	var b strings.Builder
	b.WriteString("<title>" + html.EscapeString(title) + "</title>\n")
	b.WriteString(`<link rel="icon" href="` + html.EscapeString(icon) + `" />` + "\n")
	if h.JSON != "" {
		b.WriteString(`<script type="application/json" id="branding-data">` +
			strings.ReplaceAll(h.JSON, "<", `\u003c`) + `</script>` + "\n")
	}
	return b.String()
}

func serveIndex(w http.ResponseWriter, index []byte, head Head) {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	nonce := base64.StdEncoding.EncodeToString(b)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; "))
	out := bytes.ReplaceAll(index, []byte(headPlaceholder), []byte(renderHead(head)))
	_, _ = w.Write(bytes.ReplaceAll(out, []byte(noncePlaceholder), []byte(nonce)))
}

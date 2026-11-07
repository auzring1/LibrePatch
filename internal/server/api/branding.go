package api

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/auzring1/librepatch/internal/server/branding"
	"github.com/auzring1/librepatch/internal/shared/brand"
)

func (s *server) brandingSvc(w http.ResponseWriter) bool {
	if s.Branding == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "Branding is not available.")
		return false
	}
	return true
}

// productName is the product name shown to people: the configured override, else the default.
func (s *server) productName(r *http.Request) string {
	if s.Branding != nil {
		if p, err := s.Branding.Public(r.Context()); err == nil && p.ProductName != "" {
			return p.ProductName
		}
	}
	return brand.Name
}

// GET /branding: what the signed-out pages show (names, colors, login texts, support contact, image links).
// Public on purpose: the login page needs it.
func (s *server) getPublicBranding(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	p, err := s.Branding.Public(r.Context())
	if err != nil {
		s.Log.Error("public branding", "err", err)
		internalError(w)
		return
	}
	etag := `"` + p.Version + `"`
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// GET /branding/assets/{kind}: one image. Public (the login page shows the logo). The bytes were produced by the
// server's own PNG encoder, and the response carries headers that stop a browser from treating it as anything else.
func (s *server) getBrandingAsset(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	kind := r.PathValue("kind")
	org, err := s.Branding.DefaultOrg(r.Context())
	if err != nil {
		internalError(w)
		return
	}
	a, err := s.Branding.Asset(r.Context(), org, kind)
	if errors.Is(err, branding.ErrNoAsset) || org.String() == "00000000-0000-0000-0000-000000000000" {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.Log.Error("branding asset", "err", err)
		internalError(w)
		return
	}
	h := w.Header()
	etag := `"` + a.SHA256 + `"`
	h.Set("Content-Type", "image/png")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Content-Disposition", "inline")
	h.Set("ETag", etag)
	if r.URL.Query().Get("v") != "" {
		h.Set("Cache-Control", "public, max-age=86400, immutable") // the address changes with the image
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(a.Content)
}

func (s *server) brandingActor(r *http.Request) branding.Actor {
	p := principalFrom(r)
	return branding.Actor{Org: p.OrgID, User: p.UserID, IP: clientIP(r)}
}

// brandingFail maps a service error to a response.
func (s *server) brandingFail(w http.ResponseWriter, err error) {
	var ve *branding.ValidationError
	var ie *branding.ImageError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: errorBody{Code: "invalid_branding", Message: "Some branding settings are not valid.", Fields: ve.Fields}})
	case errors.As(err, &ie):
		writeError(w, http.StatusUnprocessableEntity, "invalid_image", ie.Msg)
	case errors.Is(err, branding.ErrNoAsset):
		writeError(w, http.StatusNotFound, "not_found", "There is no image in that slot.")
	default:
		s.Log.Error("branding", "err", err)
		internalError(w)
	}
}

// GET /settings/branding (administrators).
func (s *server) getBranding(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	v, err := s.Branding.View(r.Context(), principalFrom(r).OrgID)
	if err != nil {
		s.brandingFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// PUT /settings/branding: the texts and colors (administrators; audited with before and after).
func (s *server) putBranding(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	var in branding.Settings
	if !decode(w, r, &in) {
		return
	}
	v, err := s.Branding.Update(r.Context(), s.brandingActor(r), in)
	if err != nil {
		s.brandingFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// PUT /settings/branding/assets/{kind}: the raw PNG or JPEG as the body.
func (s *server) putBrandingAsset(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	kind := r.PathValue("kind")
	if !branding.ValidKind(kind) {
		writeError(w, http.StatusNotFound, "not_found", "Unknown image slot.")
		return
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "image/png", "image/jpeg":
	case "image/svg+xml":
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "SVG images are not accepted (they can carry scripts). Use a PNG or JPEG.")
		return
	default:
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send the image as image/png or image/jpeg.")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, branding.MaxUploadBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "The image is larger than 512 KiB.")
		} else {
			badRequest(w, "The upload could not be read.")
		}
		return
	}
	v, err := s.Branding.PutAsset(r.Context(), s.brandingActor(r), kind, data)
	if err != nil {
		s.brandingFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// DELETE /settings/branding/assets/{kind}.
func (s *server) deleteBrandingAsset(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	v, err := s.Branding.DeleteAsset(r.Context(), s.brandingActor(r), r.PathValue("kind"))
	if err != nil {
		s.brandingFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// POST /settings/branding/reset: back to the defaults.
func (s *server) resetBranding(w http.ResponseWriter, r *http.Request) {
	if !s.brandingSvc(w) {
		return
	}
	v, err := s.Branding.Reset(r.Context(), s.brandingActor(r))
	if err != nil {
		s.brandingFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

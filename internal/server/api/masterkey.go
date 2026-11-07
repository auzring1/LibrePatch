package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/server/keyack"
)

// keyPendingAllowed lists what a signed-in person may still call while the master key has not been saved: the screen that
// shows it, signing out, and what the console needs to draw that screen.
func keyPendingAllowed(path string) bool {
	switch strings.TrimSuffix(path, "/") {
	case "/api/v1/auth/session", "/api/v1/auth/logout", "/api/v1/security/master-key", "/api/v1/security/master-key/acknowledge",
		"/api/v1/me/preferences":
		return true
	}
	return false
}

func (s *server) keyPending() bool { return s.KeyAck.Pending() }

// requireInteractive refuses an API token. The master key decrypts everything the server keeps secret, so only a person
// signed in to the console may see it or confirm that it was saved; a script holding settings:write must not be able to
// read the key and then type its last six characters to clear the warning.
func requireInteractive(w http.ResponseWriter, p *Principal) bool {
	if p.TokenID != "" {
		writeError(w, http.StatusForbidden, "forbidden", "The master key can only be handled from a signed-in console session, not with an API token.")
		return false
	}
	return true
}

// getMasterKey: GET /security/master-key. Shows the key the stack generated for itself, once, until it is saved.
func (s *server) getMasterKey(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if !requireInteractive(w, p) {
		return
	}
	k, err := s.KeyAck.View()
	if errors.Is(err, keyack.ErrNotPending) {
		writeError(w, http.StatusNotFound, "not_found", "There is no master key to show. It was saved when the stack was set up.")
		return
	}
	if err != nil {
		internalError(w)
		return
	}
	s.audit(r, p, "master_key.view", "master_key", []string{k.KeyID}, map[string]any{"key_id": k.KeyID})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"key": k.Grouped, "key_id": k.KeyID, "generated_at": k.GeneratedAt.UTC().Format(time.RFC3339)})
}

// acknowledgeMasterKey: POST /security/master-key/acknowledge {confirm}. The last six digits prove the key was looked at.
func (s *server) acknowledgeMasterKey(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if !requireInteractive(w, p) {
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.KeyAck.Pending() {
		writeError(w, http.StatusNotFound, "not_found", "The master key has already been saved.")
		return
	}
	if !s.KeyAck.Confirms(req.Confirm) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", "That is not the end of the master key. Type the last six characters of the key you saved.")
		return
	}
	k, _ := s.KeyAck.View()
	if err := s.KeyAck.Acknowledge(r.Context(), p.UserID); err != nil {
		if errors.Is(err, keyack.ErrNotPending) {
			writeError(w, http.StatusNotFound, "not_found", "The master key has already been saved.")
			return
		}
		s.Log.Error("acknowledge master key", "err", err)
		internalError(w)
		return
	}
	s.audit(r, p, "master_key.acknowledge", "master_key", []string{k.KeyID}, map[string]any{"key_id": k.KeyID})
	w.WriteHeader(http.StatusNoContent)
}

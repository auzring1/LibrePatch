package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Status is written to status.json so `install` (and support staff) can see
// what the service is doing without reading logs.
type Status struct {
	State     string    `json:"state"` // starting|enrolling|pending_approval|connecting|connected|rejected|error
	DeviceID  string    `json:"device_id,omitempty"`
	Message   string    `json:"message,omitempty"`
	Server    string    `json:"server,omitempty"`
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WriteStatus writes status.json atomically.
func WriteStatus(dir string, s Status) {
	s.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	p := filepath.Join(dir, "status.json")
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

// ReadStatus reads status.json.
func ReadStatus(dir string) (Status, error) {
	var s Status
	b, err := os.ReadFile(filepath.Join(dir, "status.json")) // #nosec G304
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

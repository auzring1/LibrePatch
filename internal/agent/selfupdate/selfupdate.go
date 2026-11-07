// Package selfupdate holds the agent's side of A/B self-update (docs/ARCHITECTURE.md §10):
// the durable state of an update in flight, the operating-system operations it needs
// (Platform) and the rollback safety net that runs from the OLD binary when the new one never
// proves itself healthy.
//
// Sequence: the job engine verifies the vendor-signed release, stages the new binary into the
// inactive slot, arms a one-shot rollback task that runs the CURRENT binary, switches the
// service to the new slot and restarts. The new version writes "healthy" after its first
// successful server handshake and disarms the task; if that never happens the task restores the
// old slot and restarts the service.
package selfupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Status values of an update in flight.
const (
	StatusSwitching  = "switching"   // service now points at ToSlot; waiting for proof of health
	StatusHealthy    = "healthy"     // the new version completed a handshake
	StatusRolledBack = "rolled_back" // the safety net restored FromSlot
)

// RollbackWindow is how long the new version has to become healthy.
const RollbackWindow = 10 * time.Minute

// State is the contents of update.json in the agent data directory. It is a plain file (not the
// bbolt state) because the rollback task runs in a separate process while the service holds the
// database open.
type State struct {
	JobID       string `json:"job_id"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	FromSlot    string `json:"from_slot"`
	ToSlot      string `json:"to_slot"`
	FromExe     string `json:"from_exe"`
	ToExe       string `json:"to_exe"`
	StartedAt   int64  `json:"started_at"`
	Deadline    int64  `json:"deadline"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
}

// ErrNone means no update state exists.
var ErrNone = errors.New("selfupdate: no update in progress")

func statePath(dir string) string { return filepath.Join(dir, "update.json") }

// Load reads the state file.
func Load(dir string) (*State, error) {
	b, err := os.ReadFile(statePath(dir)) // #nosec G304 -- fixed name inside the ACL-protected data directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNone
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("selfupdate: corrupt update.json: %w", err)
	}
	return &s, nil
}

// Save writes the state atomically.
func Save(dir string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(dir))
}

// Clear removes the state file.
func Clear(dir string) error {
	if err := os.Remove(statePath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Platform is what self-update needs from the operating system.
type Platform interface {
	// Current returns the slot the running service uses and the path of its binary.
	Current() (slot, exe string, err error)
	// StageInactive copies src into the inactive slot (replacing whatever is there) and returns
	// that slot and the binary's path.
	StageInactive(src string) (slot, exe string, err error)
	// Switch points the service at the given slot.
	Switch(slot string) error
	// ScheduleRollback arms a one-shot task that runs `exe rollback-check` at the given time
	// as the service account. Replaces any earlier task.
	ScheduleRollback(at time.Time, exe string) error
	// CancelRollback removes the task (no error if absent).
	CancelRollback() error
	// Restart makes the running service process exit so the service manager starts it again
	// (from the in-process side; returns immediately).
	Restart() error
	// Bounce stops and starts the service from outside the service process (rollback-check).
	Bounce() error
}

// RollbackCheck is the body of `librepatch-agent rollback-check`, run by the one-shot task from the
// OLD binary. It returns what it did, for the log.
func RollbackCheck(dir string, p Platform, now time.Time) (string, error) {
	st, err := Load(dir)
	if errors.Is(err, ErrNone) {
		_ = p.CancelRollback()
		return "no update in progress", nil
	}
	if err != nil {
		return "", err
	}
	if st.Status != StatusSwitching {
		_ = p.CancelRollback()
		return "update is " + st.Status + "; nothing to roll back", nil
	}
	if now.Unix() < st.Deadline {
		return "", fmt.Errorf("selfupdate: too early (deadline %s)", time.Unix(st.Deadline, 0).Format(time.RFC3339))
	}
	if err := p.Switch(st.FromSlot); err != nil {
		return "", fmt.Errorf("selfupdate: cannot restore slot %s: %w", st.FromSlot, err)
	}
	st.Status = StatusRolledBack
	st.Message = fmt.Sprintf("version %s did not become healthy within %s; restored %s", st.ToVersion, RollbackWindow, st.FromVersion)
	if err := Save(dir, st); err != nil {
		return "", err
	}
	_ = p.CancelRollback()
	if err := p.Bounce(); err != nil {
		return "", fmt.Errorf("selfupdate: restored slot %s but could not restart the service: %w", st.FromSlot, err)
	}
	return st.Message, nil
}

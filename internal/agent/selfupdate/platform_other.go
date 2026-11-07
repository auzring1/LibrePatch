//go:build !windows

package selfupdate

import (
	"encoding/json"
	"errors"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Dev is the non-Windows stand-in: slots are directories under <dataDir>/slots and "the service"
// is whatever Hook does. It lets the whole update sequence (including the rollback task and the
// state machine) run in tests, the browser test and demos without Windows.
type Dev struct {
	Dir string
	// RestartHook runs when the engine asks the service to restart (a test starts the "new" agent).
	RestartHook func()
}

// Default returns the platform for this operating system.
func Default(dataDir string, restart func()) Platform {
	d := NewDev(dataDir)
	d.RestartHook = restart
	return d
}

// NewDev returns the development platform rooted at dataDir.
func NewDev(dataDir string) *Dev { return &Dev{Dir: dataDir} }

func (d *Dev) active() string {
	b, err := os.ReadFile(filepath.Join(d.Dir, "active-slot")) // #nosec G304 -- fixed name
	if err != nil || (string(b) != "a" && string(b) != "b") {
		return "a"
	}
	return string(b)
}

func (d *Dev) exe(slot string) string {
	return filepath.Join(d.Dir, "slots", "slot-"+slot, strings.TrimSuffix(brand.AgentExe, ".exe"))
}

// Current implements Platform.
func (d *Dev) Current() (string, string, error) { s := d.active(); return s, d.exe(s), nil }

// StageInactive implements Platform.
func (d *Dev) StageInactive(src string) (string, string, error) {
	slot := "b"
	if d.active() == "b" {
		slot = "a"
	}
	dst := d.exe(slot)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", "", err
	}
	in, err := os.Open(src) // #nosec G304 -- verified staged file
	if err != nil {
		return "", "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700) // #nosec G302 G304 -- development stand-in
	if err != nil {
		return "", "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", "", err
	}
	if err := out.Close(); err != nil {
		return "", "", err
	}
	return slot, dst, os.Rename(dst+".new", dst)
}

// Switch implements Platform.
func (d *Dev) Switch(slot string) error {
	if slot != "a" && slot != "b" {
		return errors.New("bad slot")
	}
	return os.WriteFile(filepath.Join(d.Dir, "active-slot"), []byte(slot), 0o600)
}

type devTask struct {
	At  int64  `json:"at"`
	Exe string `json:"exe"`
}

// ScheduleRollback implements Platform.
func (d *Dev) ScheduleRollback(at time.Time, exe string) error {
	b, _ := json.Marshal(devTask{At: at.Unix(), Exe: exe})
	return os.WriteFile(filepath.Join(d.Dir, "rollback-task.json"), b, 0o600)
}

// Task returns the armed task, if any (tests).
func (d *Dev) Task() (at time.Time, exe string, armed bool) {
	b, err := os.ReadFile(filepath.Join(d.Dir, "rollback-task.json")) // #nosec G304 -- fixed name
	if err != nil {
		return time.Time{}, "", false
	}
	var t devTask
	if json.Unmarshal(b, &t) != nil {
		return time.Time{}, "", false
	}
	return time.Unix(t.At, 0), t.Exe, true
}

// CancelRollback implements Platform.
func (d *Dev) CancelRollback() error {
	if err := os.Remove(filepath.Join(d.Dir, "rollback-task.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Restart implements Platform.
func (d *Dev) Restart() error {
	if d.RestartHook != nil {
		go d.RestartHook()
	}
	return nil
}

// Bounce implements Platform.
func (d *Dev) Bounce() error {
	if d.RestartHook != nil {
		go d.RestartHook()
	}
	return nil
}

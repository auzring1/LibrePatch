//go:build windows

package inventory

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Watcher signals when software or user inventory may have changed. It blocks
// in the kernel on registry change notifications: zero CPU while idle.
type Watcher struct {
	events chan struct{}
	stop   windows.Handle // manual-reset event, set on Close
	wg     sync.WaitGroup
	log    *slog.Logger

	mu       sync.Mutex
	userKeys map[string]bool // watched "sid" values
	closed   bool
}

// Events delivers (coalesced) change notifications.
func (w *Watcher) Events() <-chan struct{} { return w.events }

type watchTarget struct {
	root    registry.Key
	path    string
	subtree bool
}

// NewWatcher starts watching the registry locations that reflect installs,
// uninstalls, profile changes and AppX registrations.
func NewWatcher(log *slog.Logger) (*Watcher, error) {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	w := &Watcher{events: make(chan struct{}, 1), stop: stop, log: log, userKeys: map[string]bool{}}
	for _, t := range []watchTarget{
		{registry.LOCAL_MACHINE, hklmUninstall, true},
		{registry.LOCAL_MACHINE, hklmUninstall32, true},
		{registry.LOCAL_MACHINE, appxStore, true},
		{registry.LOCAL_MACHINE, profileListKey, true},
	} {
		w.start(t)
	}
	// HKU subkeys appear and disappear as users log on and off; each change
	// re-registers the per-user watchers.
	w.start(watchTarget{registry.USERS, "", false})
	w.refreshUsers()
	return w, nil
}

// Close stops all watchers.
func (w *Watcher) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	_ = windows.SetEvent(w.stop)
	w.wg.Wait()
	_ = windows.CloseHandle(w.stop)
}

func (w *Watcher) emit() {
	select {
	case w.events <- struct{}{}:
	default: // one pending notification is enough
	}
}

func (w *Watcher) start(t watchTarget) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.watch(t)
	}()
}

// refreshUsers ensures per-user Uninstall watchers exist for every loaded hive.
func (w *Watcher) refreshUsers() {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	sids, _ := k.ReadSubKeyNames(-1)
	_ = k.Close()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	for _, sid := range sids {
		if !IsUserSID(sid) || w.userKeys[sid] {
			continue
		}
		w.userKeys[sid] = true
		w.start(watchTarget{registry.USERS, sid + `\` + userUninstall, true})
		w.start(watchTarget{registry.USERS, sid + `\` + userUninstall32, true})
	}
}

// watch blocks on notifications for one location. If the key does not exist
// yet it watches the nearest existing ancestor (non-recursively) so that the
// key's creation is noticed, then re-resolves.
func (w *Watcher) watch(t watchTarget) {
	ev, err := windows.CreateEvent(nil, 0, 0, nil) // auto-reset
	if err != nil {
		w.log.Error("create watch event", "err", err)
		return
	}
	defer windows.CloseHandle(ev)
	for {
		key, exact := openNearest(t)
		if key == 0 {
			if w.sleepOrStop(30 * time.Second) {
				return
			}
			continue
		}
		subtree := t.subtree && exact
		const filter = 0x1 | 0x4 // REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET
		if err := windows.RegNotifyChangeKeyValue(windows.Handle(key), subtree, filter, ev, true); err != nil {
			_ = key.Close()
			w.log.Warn("registry watch failed", "path", t.path, "err", err)
			if w.sleepOrStop(60 * time.Second) {
				return
			}
			continue
		}
		res, _ := windows.WaitForMultipleObjects([]windows.Handle{ev, w.stop}, false, windows.INFINITE)
		_ = key.Close()
		if res != windows.WAIT_OBJECT_0 { // stop event or error
			return
		}
		if t.root == registry.USERS && t.path == "" {
			w.refreshUsers()
		}
		w.emit()
	}
}

func (w *Watcher) sleepOrStop(d time.Duration) bool {
	res, _ := windows.WaitForSingleObject(w.stop, uint32(d/time.Millisecond)) // #nosec G115
	return res == windows.WAIT_OBJECT_0
}

// openNearest opens the target key, or its closest existing ancestor.
func openNearest(t watchTarget) (registry.Key, bool) {
	path := t.path
	exact := true
	for {
		k, err := registry.OpenKey(t.root, path, registry.NOTIFY)
		if err == nil {
			return k, exact
		}
		if path == "" {
			return 0, false
		}
		exact = false
		if i := strings.LastIndex(path, `\`); i >= 0 {
			path = path[:i]
		} else {
			path = ""
		}
	}
}

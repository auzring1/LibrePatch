//go:build !windows

package inventory

import (
	"log/slog"
)

// RunBackground runs fn directly (background priority is a Windows concept).
func RunBackground(fn func()) { fn() }

// Watcher is a no-op off Windows; the daily reconcile still runs.
type Watcher struct{ events chan struct{} }

// NewWatcher returns a watcher that never fires.
func NewWatcher(*slog.Logger) (*Watcher, error) { return &Watcher{events: make(chan struct{})}, nil }

// Events delivers change notifications (never, off Windows).
func (w *Watcher) Events() <-chan struct{} { return w.events }

// Close is a no-op.
func (w *Watcher) Close() {}

// Package logging configures the agent's structured log with size-based rotation.
package logging

import (
	"io"
	"log/slog"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

// New returns a JSON logger writing to dir/agent.log (5 MiB x 3 files) and,
// if console is non-nil, also to console.
func New(dir, level string, console io.Writer) *slog.Logger {
	var w io.Writer = &lumberjack.Logger{Filename: filepath.Join(dir, "agent.log"), MaxSize: 5, MaxBackups: 3, Compress: true}
	if console != nil {
		w = io.MultiWriter(w, console)
	}
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

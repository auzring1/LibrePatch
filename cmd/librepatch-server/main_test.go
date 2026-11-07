package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdleMarksReadyThenStopsCleanly(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- idleUntilStopped(ctx, ready) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ready file never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Setenv("LIBREPATCH_HEALTH_FILE", ready)
	if err := healthcheck(); err != nil {
		t.Fatalf("healthy once the file exists: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("returned before it was stopped: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop after the context was cancelled")
	}
	if _, err := os.Stat(ready); !os.IsNotExist(err) {
		t.Fatalf("the ready file should be removed on the way out (err=%v)", err)
	}
	if err := healthcheck(); err == nil {
		t.Fatal("unhealthy once the file is gone")
	}
}

func TestIdleWithoutAReadyFileStillWaits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- idleUntilStopped(ctx, "") }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop")
	}
}

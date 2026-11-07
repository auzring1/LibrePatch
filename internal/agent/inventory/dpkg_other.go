//go:build !windows && !linux

package inventory

import (
	"context"
)

// NewCollector returns an empty collector on unsupported development platforms.
func NewCollector() Collector { return emptyCollector{} }

type emptyCollector struct{}

func (emptyCollector) Collect(context.Context) (*Scan, error) { return &Scan{}, nil }

// Package wu talks to the Windows Update Agent (WUA) on behalf of the job engine: scan for
// updates, download and install exactly the updates a signed job names, hide and unhide updates,
// and report who is in charge of updates on the machine (docs/ARCHITECTURE.md §9).
//
// The Windows implementation drives WUA through COM; every other platform gets a scripted
// development client (used by tests, the browser test and the demo on Linux, never shipped).
package wu

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	sharedtext "github.com/auzring1/librepatch/internal/shared/text"
)

// MaxUpdates bounds a scan snapshot; a device with more applicable updates is reported truncated.
const MaxUpdates = 1000

// ErrUnavailable means Windows Update cannot be used on this machine right now (service disabled,
// no network path to the configured source, COM failure). The message is meant for administrators.
var ErrUnavailable = errors.New("wu: Windows Update is not available")

// Options select the update service a scan or install talks to.
type Options struct {
	Service        agentv1.WuService
	IncludeDrivers bool
}

// InstallResult is the outcome of one Install call.
type InstallResult struct {
	Results        []*agentv1.WuUpdateResult
	RebootRequired bool
	Log            string // short human-readable trace (bounded by the caller)
}

// Client is the Windows Update Agent as the engine sees it.
type Client interface {
	// Scan returns the applicable updates that are not installed (missing, downloaded, hidden,
	// failed) plus installed updates that wait for a restart.
	Scan(ctx context.Context, o Options) ([]*agentv1.WuUpdate, error)
	// Install downloads and installs exactly the listed updates (found by a fresh scan, never by
	// title). Updates the scan no longer offers are reported NOT_APPLICABLE.
	Install(ctx context.Context, o Options, refs []*agentv1.WuUpdateRef) (*InstallResult, error)
	// Hide hides (or unhides) updates so Windows does not offer them.
	Hide(ctx context.Context, o Options, refs []*agentv1.WuUpdateRef, hide bool) error
	// Policy reports who manages updates on this machine.
	Policy() *agentv1.WuPolicyInfo
}

// Snapshot builds the report the agent sends after a scan.
func Snapshot(updates []*agentv1.WuUpdate, pol *agentv1.WuPolicyInfo, reboot bool, o Options, scanErr error, now time.Time) *agentv1.WuInventory {
	s := &agentv1.WuInventory{Policy: pol, RebootRequired: reboot, ScannedAt: now.Unix(), Service: int32(o.Service)} // #nosec G115 -- enum value
	if scanErr != nil {
		s.ScanError = bound(scanErr.Error(), 512)
		return s
	}
	if len(updates) > MaxUpdates {
		updates, s.Truncated = updates[:MaxUpdates], true
	}
	s.Updates = updates
	return s
}

func bound(s string, n int) string { return sharedtext.Truncate(s, n) }

// InActiveHours reports whether t lies inside the device-local active hours (which may wrap
// midnight). Equal start and end, or nil, mean there are none.
func InActiveHours(ah *agentv1.ActiveHours, t time.Time, loc *time.Location) bool {
	if ah == nil || ah.StartMinute == ah.EndMinute {
		return false
	}
	lt := t.In(loc)
	m := uint32(lt.Hour()*60 + lt.Minute()) // #nosec G115 -- 0..1439
	if ah.StartMinute < ah.EndMinute {
		return m >= ah.StartMinute && m < ah.EndMinute
	}
	return m >= ah.StartMinute || m < ah.EndMinute
}

// NextOutsideActiveHours returns t if it is already outside the active hours, otherwise the
// moment the active hours end.
func NextOutsideActiveHours(ah *agentv1.ActiveHours, t time.Time, loc *time.Location) time.Time {
	if !InActiveHours(ah, t, loc) {
		return t
	}
	lt := t.In(loc)
	end := time.Date(lt.Year(), lt.Month(), lt.Day(), int(ah.EndMinute)/60, int(ah.EndMinute)%60, 0, 0, loc)
	if !end.After(lt) {
		end = end.AddDate(0, 0, 1)
	}
	return end
}

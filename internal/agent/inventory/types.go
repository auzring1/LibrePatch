// Package inventory collects software and user inventory on the endpoint and
// turns successive scans into revisioned deltas for the server (PROTOCOL §6).
//
// Scanning logic is platform-independent and works against the small
// Platform/RegNode interfaces, so it is unit-tested on Linux with fakes;
// the Windows implementation lives in *_windows.go.
package inventory

import (
	"context"
	"strings"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/shared/text"
)

const (
	// MaxItems caps the software list (server limit: 25k). Beyond it the
	// scan is truncated and flagged.
	MaxItems = 25000
	// MaxDeltaItems: larger deltas are sent as a full snapshot instead.
	MaxDeltaItems = 5000
	// ChunkSize is the number of items per message of a full snapshot.
	ChunkSize = 250

	maxName, maxVersion, maxPublisher, maxPath, maxKey = 512, 128, 512, 2048, 512
)

// Group selects a set of item keys by (source, scope, SID); empty fields are
// wildcards. Failed groups tell the differ not to treat their absent items
// as removed.
type Group struct {
	Source agentv1.SoftwareSource
	Scope  agentv1.SoftwareScope
	SID    string
}

func (g Group) matches(k *agentv1.SoftwareItemKey) bool {
	return (g.Source == 0 || g.Source == k.Source) &&
		(g.Scope == 0 || g.Scope == k.Scope) &&
		(g.SID == "" || g.SID == k.UserSid)
}

// Scan is the result of one collection pass.
type Scan struct {
	Items     []*agentv1.SoftwareItem
	Users     []*agentv1.DeviceUser
	Truncated bool
	// Failed lists groups that could not be read this pass.
	Failed []Group
	// Warnings are non-fatal problems, for the log.
	Warnings []string
}

// Collector produces a Scan. Implementations must be safe to call from one
// goroutine at a time and cheap enough to run in the background.
type Collector interface {
	Collect(ctx context.Context) (*Scan, error)
}

// ItemKeyBytes is the canonical serialization of an item key, used as the map
// and bbolt key of the acknowledged snapshot.
func ItemKeyBytes(k *agentv1.SoftwareItemKey) []byte {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(k)
	return b
}

// ItemHash fingerprints every reported field of an item.
func ItemHash(it *agentv1.SoftwareItem) []byte {
	return hashMsg(it)
}

// clip makes s valid UTF-8 (protobuf rejects invalid strings, and registry
// data can contain anything) and cuts it to at most max bytes on a rune boundary.
func clip(s string, max int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	return text.Truncate(s, max)
}

// sanitize bounds and cleans an item before it is reported.
func sanitize(it *agentv1.SoftwareItem) {
	it.Name = clip(strings.TrimSpace(it.Name), maxName)
	it.Version = clip(strings.TrimSpace(it.Version), maxVersion)
	it.Publisher = clip(strings.TrimSpace(it.Publisher), maxPublisher)
	it.InstallLocation = clip(it.InstallLocation, maxPath)
	it.UninstallString = clip(it.UninstallString, maxPath)
	it.QuietUninstallString = clip(it.QuietUninstallString, maxPath)
	if it.Key != nil {
		it.Key.ItemKey = clip(it.Key.ItemKey, maxKey)
	}
}

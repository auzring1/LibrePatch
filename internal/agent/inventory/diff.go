package inventory

import (
	"bytes"
	"sort"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Snapshot maps an item key (ItemKeyBytes) to the hash of the item as last
// acknowledged by the server.
type Snapshot map[string][]byte

// SnapshotOf builds the snapshot for a list of items.
func SnapshotOf(items []*agentv1.SoftwareItem) Snapshot {
	s := make(Snapshot, len(items))
	for _, it := range items {
		s[string(ItemKeyBytes(it.Key))] = ItemHash(it)
	}
	return s
}

// Diff compares the acknowledged snapshot with a fresh scan.
//
// Items of groups that failed to scan are never reported as removed: a
// partial scan must not make the server forget software.
// next is the snapshot the server will hold once the delta is applied.
func Diff(prev Snapshot, scan *Scan) (upserts []*agentv1.SoftwareItem, removes []*agentv1.SoftwareItemKey, next Snapshot) {
	next = make(Snapshot, len(scan.Items))
	for _, it := range scan.Items {
		k := string(ItemKeyBytes(it.Key))
		h := ItemHash(it)
		next[k] = h
		if old, ok := prev[k]; !ok || !bytes.Equal(old, h) {
			upserts = append(upserts, it)
		}
	}
	var gone []string
	for k := range prev {
		if _, ok := next[k]; !ok {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		key := &agentv1.SoftwareItemKey{}
		if proto.Unmarshal([]byte(k), key) != nil {
			continue // corrupt entry: drop it from the snapshot
		}
		if failedGroup(scan.Failed, key) {
			next[k] = prev[k] // keep: we could not look
			continue
		}
		removes = append(removes, key)
	}
	return upserts, removes, next
}

func failedGroup(failed []Group, k *agentv1.SoftwareItemKey) bool {
	for _, g := range failed {
		if g.matches(k) {
			return true
		}
	}
	return false
}

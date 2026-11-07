package catalog

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
)

//go:embed overlay.json
var overlayJSON []byte

//go:embed matrix_results.json
var matrixJSON []byte

// OverlayEntry is knowledge about a package that its manifest lacks. The built-in entries carry only the first three
// fields; entries from a signed overlay (D122) fill in the rest.
type OverlayEntry struct {
	Identifier   string `json:"identifier"`
	SelfUpdating bool   `json:"self_updating"`
	Note         string `json:"note,omitempty"`

	// Source is the label of the overlay the entry came from ("" for the built-in one).
	Source string `json:"source,omitempty"`
	// SelfUpdatingSet is whether the entry says anything about self-updating; if not, the built-in answer applies.
	SelfUpdatingSet bool        `json:"-"`
	Verified        bool        `json:"verified,omitempty"`
	VerifiedNote    string      `json:"verified_note,omitempty"`
	SilentArgs      []string    `json:"silent_args,omitempty"`
	ExtraDetection  []Detection `json:"extra_detection,omitempty"`
	Processes       []string    `json:"processes,omitempty"`
}

// MatrixResult is one passing VM-matrix run (docs/ARCHITECTURE.md §7.9).
type MatrixResult struct {
	Identifier string `json:"identifier"`
	Scope      string `json:"scope"` // machine | user
	OS         string `json:"os"`
	RunID      string `json:"run_id"`
	PassedAt   string `json:"passed_at"`
}

// Overlay is the embedded catalog overlay plus VM-matrix results.
type Overlay struct {
	byID    map[string]OverlayEntry
	results map[string][]MatrixResult

	mu  sync.RWMutex
	dyn map[uuid.UUID]map[string]OverlayEntry // per organization, from the signed overlays an administrator added
}

// LoadOverlay parses the embedded data.
func LoadOverlay() *Overlay {
	o := &Overlay{byID: map[string]OverlayEntry{}, results: map[string][]MatrixResult{}, dyn: map[uuid.UUID]map[string]OverlayEntry{}}
	var ov struct {
		Packages []OverlayEntry `json:"packages"`
	}
	_ = json.Unmarshal(overlayJSON, &ov)
	for _, e := range ov.Packages {
		e.SelfUpdatingSet = true
		o.byID[strings.ToLower(e.Identifier)] = e
	}
	var res []MatrixResult
	_ = json.Unmarshal(matrixJSON, &res)
	for _, r := range res {
		k := strings.ToLower(r.Identifier)
		o.results[k] = append(o.results[k], r)
	}
	return o
}

// Entry returns the overlay entry for an identifier.
func (o *Overlay) Entry(id string) (OverlayEntry, bool) {
	e, ok := o.byID[strings.ToLower(id)]
	return e, ok
}

// Verified reports whether the package has a passing matrix run for the scope
// ("" = any scope).
func (o *Overlay) Verified(id, scope string) bool {
	for _, r := range o.results[strings.ToLower(id)] {
		if scope == "" || r.Scope == scope {
			return true
		}
	}
	return false
}

// Known lists the overlay's packages (used to suggest imports).
func (o *Overlay) Known() []OverlayEntry {
	out := make([]OverlayEntry, 0, len(o.byID))
	for _, e := range o.byID {
		out = append(out, e)
	}
	return out
}

// SetOrg replaces the signed-overlay entries of one organization (identifier, lower case, to entry).
func (o *Overlay) SetOrg(org uuid.UUID, m map[string]OverlayEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.dyn == nil {
		o.dyn = map[uuid.UUID]map[string]OverlayEntry{}
	}
	o.dyn[org] = m
}

// EntryFor returns what is known about a package for an organization: the entry of its signed overlays (the one with the
// lowest priority number wins) where there is one, completed from the built-in entry for what it leaves unsaid.
func (o *Overlay) EntryFor(org uuid.UUID, id string) (OverlayEntry, bool) {
	key := strings.ToLower(id)
	base, haveBase := o.byID[key]
	o.mu.RLock()
	d, haveDyn := o.dyn[org][key]
	o.mu.RUnlock()
	if !haveDyn {
		return base, haveBase
	}
	if !d.SelfUpdatingSet {
		d.SelfUpdating = base.SelfUpdating
	}
	if d.Note == "" {
		d.Note = base.Note
	}
	return d, true
}

// VerifiedFor reports whether a package counts as verified for an organization, and by whom: "tests" (a passing VM-matrix
// run) or the label of the overlay that vouches for it.
func (o *Overlay) VerifiedFor(org uuid.UUID, id, scope string) (bool, string) {
	if o.Verified(id, scope) {
		return true, "tests"
	}
	if e, ok := o.EntryFor(org, id); ok && e.Verified {
		return true, e.Source
	}
	return false, ""
}

// KnownFor lists the packages the overlays know about for an organization, the signed overlays' entries first.
func (o *Overlay) KnownFor(org uuid.UUID) []OverlayEntry {
	seen := map[string]bool{}
	var out []OverlayEntry
	o.mu.RLock()
	for k, e := range o.dyn[org] {
		seen[k] = true
		out = append(out, e)
	}
	o.mu.RUnlock()
	for k, e := range o.byID {
		if !seen[k] {
			out = append(out, e)
		}
	}
	return out
}

// MergeOverride layers what an overlay says under an administrator's own override: the override's silent arguments and program names win
// when it has any (the overlay's are used otherwise), and the detection rules of both are used. The result is a copy; an
// override that is nil stays nil when the overlay adds nothing.
func MergeOverride(ov *dbq.PackageOverride, e OverlayEntry) *dbq.PackageOverride {
	if len(e.SilentArgs) == 0 && len(e.ExtraDetection) == 0 && len(e.Processes) == 0 {
		return ov
	}
	var out dbq.PackageOverride
	if ov != nil {
		out = *ov
	}
	if len(out.SilentArgs) == 0 {
		out.SilentArgs = append([]string(nil), e.SilentArgs...)
	}
	if len(out.Processes) == 0 {
		out.Processes = append([]string(nil), e.Processes...)
	}
	if len(e.ExtraDetection) > 0 {
		var mine []Detection
		_ = json.Unmarshal(out.ExtraDetection, &mine)
		merged := append(append([]Detection(nil), mine...), e.ExtraDetection...)
		out.ExtraDetection, _ = json.Marshal(merged)
	}
	return &out
}

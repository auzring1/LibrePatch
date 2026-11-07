// Package sbom builds CycloneDX 1.5 JSON software bills of materials for the release pipeline
// (docs/THREAT-MODEL.md supply chain, docs/VERIFYING_RELEASES.md).
//
// It is standard library only and has two sources:
//
//   - FromGoBinary reads the module list the Go linker embedded in a built binary
//     (runtime/debug.BuildInfo, also for cross-built Windows executables). That is the exact set of
//     modules compiled in, not the larger set in go.mod.
//   - FromNPMLock reads web/package-lock.json (lockfile v2/v3) and keeps the production closure.
//
// Output is deterministic: components are sorted, the timestamp is supplied by the caller (the commit
// time, SOURCE_DATE_EPOCH) and the serial number is derived from the document's own content, so building
// the same release twice gives byte-identical SBOMs and they can take part in the reproducibility check.
// Check validates the shape of a document (a subset of the CycloneDX 1.5 schema plus reference integrity).
package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"sort"
	"time"
)

// SpecVersion is the CycloneDX version written.
const SpecVersion = "1.5"

// BOM is the top-level CycloneDX document.
type BOM struct {
	Schema       string       `json:"$schema,omitempty"`
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata describes the document and the thing it describes.
type Metadata struct {
	Timestamp  string      `json:"timestamp"`
	Lifecycles []Lifecycle `json:"lifecycles,omitempty"`
	Tools      *Tools      `json:"tools,omitempty"`
	Component  *Component  `json:"component,omitempty"`
}

// Lifecycle is a CycloneDX lifecycle phase.
type Lifecycle struct {
	Phase string `json:"phase"`
}

// Tools lists the generators (CycloneDX 1.5 object form).
type Tools struct {
	Components []Component `json:"components"`
}

// Component is a CycloneDX component.
type Component struct {
	Type         string        `json:"type"`
	BOMRef       string        `json:"bom-ref,omitempty"`
	Group        string        `json:"group,omitempty"`
	Name         string        `json:"name"`
	Version      string        `json:"version,omitempty"`
	Description  string        `json:"description,omitempty"`
	Scope        string        `json:"scope,omitempty"`
	Hashes       []Hash        `json:"hashes,omitempty"`
	Licenses     []LicenseItem `json:"licenses,omitempty"`
	PURL         string        `json:"purl,omitempty"`
	ExternalRefs []ExternalRef `json:"externalReferences,omitempty"`
	Properties   []Property    `json:"properties,omitempty"`
}

// Hash is an algorithm and a hex digest.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// LicenseItem is either a license (id or name) or an SPDX expression.
type LicenseItem struct {
	License    *License `json:"license,omitempty"`
	Expression string   `json:"expression,omitempty"`
}

// License names a license.
type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// ExternalRef points at something outside the document.
type ExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property is a free-form name/value pair (namespaced "librepatch:" here).
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency lists what one component depends on.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// ToolVersion is the generator version recorded in metadata.tools.
const ToolVersion = "1"

func newBOM(epoch int64, root Component) *BOM {
	return &BOM{
		Schema:      "http://cyclonedx.org/schema/bom-1.5.schema.json", // NOSONAR: the schema's identifier, not an address anything connects to
		BOMFormat:   "CycloneDX",
		SpecVersion: SpecVersion,
		Version:     1,
		Metadata: Metadata{
			Timestamp:  time.Unix(epoch, 0).UTC().Format(time.RFC3339),
			Lifecycles: []Lifecycle{{Phase: "build"}},
			Tools: &Tools{Components: []Component{{
				Type: "application", Name: "librepatch-sbom", Version: ToolVersion,
				Description: brand.Name + " release pipeline SBOM generator (cmd/" + brand.Slug + "-sbom)",
			}}},
			Component: &root,
		},
	}
}

// finish sorts, derives the serial number from the content and returns the encoded document.
func (b *BOM) finish() ([]byte, error) {
	sort.Slice(b.Components, func(i, j int) bool { return b.Components[i].BOMRef < b.Components[j].BOMRef })
	sort.Slice(b.Dependencies, func(i, j int) bool { return b.Dependencies[i].Ref < b.Dependencies[j].Ref })
	for i := range b.Dependencies {
		sort.Strings(b.Dependencies[i].DependsOn)
	}
	b.SerialNumber = ""
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	b.SerialNumber = serialFrom(raw)
	return json.MarshalIndent(b, "", "  ")
}

// serialFrom derives an RFC 4122 style UUID (version 5 layout) from the content hash.
func serialFrom(content []byte) string {
	h := sha256.Sum256(content)
	u := h[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

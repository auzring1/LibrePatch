package sbom

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	serialRE = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// CycloneDX 1.5 hash alg enum members this project can produce or accept.
	hashLen = map[string]int{"MD5": 16, "SHA-1": 20, "SHA-256": 32, "SHA-384": 48, "SHA-512": 64, "SHA3-256": 32, "SHA3-384": 48, "SHA3-512": 64}
	// CycloneDX 1.5 component type enum.
	componentTypes = map[string]bool{
		"application": true, "framework": true, "library": true, "container": true, "platform": true,
		"operating-system": true, "device": true, "device-driver": true, "firmware": true, "file": true,
		"machine-learning-model": true, "data": true, "cryptographic-asset": true,
	}
)

// Check validates the shape of a CycloneDX 1.5 JSON document: required fields, enumerations, hash
// lengths, the purl prefix, unique bom-refs and that every dependency reference resolves. It is a
// deliberate subset of the published JSON schema (which is not vendored here), strict enough to catch
// a broken generator. Unknown fields are accepted, as the specification allows.
func Check(doc []byte) error {
	var b BOM
	dec := json.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&b); err != nil {
		return fmt.Errorf("not valid CycloneDX JSON: %w", err)
	}
	if b.BOMFormat != "CycloneDX" {
		return fmt.Errorf("bomFormat is %q, want CycloneDX", b.BOMFormat)
	}
	if b.SpecVersion != SpecVersion {
		return fmt.Errorf("specVersion is %q, want %s", b.SpecVersion, SpecVersion)
	}
	if b.Version < 1 {
		return errors.New("version must be a positive integer")
	}
	if !serialRE.MatchString(b.SerialNumber) {
		return fmt.Errorf("serialNumber %q is not a urn:uuid", b.SerialNumber)
	}
	if _, err := time.Parse(time.RFC3339, b.Metadata.Timestamp); err != nil {
		return fmt.Errorf("metadata.timestamp: %w", err)
	}
	if b.Metadata.Component == nil {
		return errors.New("metadata.component (the subject of the SBOM) is missing")
	}
	if len(b.Components) == 0 {
		return errors.New("components is empty")
	}

	refs := map[string]bool{}
	add := func(where string, c *Component) error {
		if err := checkComponent(where, c); err != nil {
			return err
		}
		if c.BOMRef == "" {
			return fmt.Errorf("%s: bom-ref is required so dependencies can point at it", where)
		}
		if refs[c.BOMRef] {
			return fmt.Errorf("%s: duplicate bom-ref %q", where, c.BOMRef)
		}
		refs[c.BOMRef] = true
		return nil
	}
	if err := add("metadata.component", b.Metadata.Component); err != nil {
		return err
	}
	for i := range b.Components {
		if err := add(fmt.Sprintf("components[%d]", i), &b.Components[i]); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for i, d := range b.Dependencies {
		if !refs[d.Ref] {
			return fmt.Errorf("dependencies[%d]: ref %q is not a component", i, d.Ref)
		}
		if seen[d.Ref] {
			return fmt.Errorf("dependencies[%d]: duplicate entry for %q", i, d.Ref)
		}
		seen[d.Ref] = true
		for _, t := range d.DependsOn {
			if !refs[t] {
				return fmt.Errorf("dependencies[%d]: %q depends on unknown ref %q", i, d.Ref, t)
			}
		}
	}
	return nil
}

func checkComponent(where string, c *Component) error {
	if !componentTypes[c.Type] {
		return fmt.Errorf("%s: type %q is not a CycloneDX component type", where, c.Type)
	}
	if c.Name == "" {
		return fmt.Errorf("%s: name is required", where)
	}
	if c.PURL != "" && !strings.HasPrefix(c.PURL, "pkg:") {
		return fmt.Errorf("%s: purl %q must start with the pkg: scheme", where, c.PURL)
	}
	for j, h := range c.Hashes {
		n, ok := hashLen[h.Alg]
		if !ok {
			return fmt.Errorf("%s: hashes[%d]: unknown alg %q", where, j, h.Alg)
		}
		raw, err := hex.DecodeString(h.Content)
		if err != nil || len(raw) != n || h.Content != strings.ToLower(h.Content) {
			return fmt.Errorf("%s: hashes[%d]: content is not %d bytes of lowercase hex", where, j, n)
		}
	}
	for j, l := range c.Licenses {
		switch {
		case l.License != nil && l.Expression == "":
			if (l.License.ID == "") == (l.License.Name == "") {
				return fmt.Errorf("%s: licenses[%d]: exactly one of id and name is required", where, j)
			}
		case l.License == nil && l.Expression != "":
		default:
			return fmt.Errorf("%s: licenses[%d]: exactly one of license and expression is required", where, j)
		}
	}
	for j, r := range c.ExternalRefs {
		if r.Type == "" || r.URL == "" {
			return fmt.Errorf("%s: externalReferences[%d]: type and url are required", where, j)
		}
	}
	for j, p := range c.Properties {
		if p.Name == "" {
			return fmt.Errorf("%s: properties[%d]: name is required", where, j)
		}
	}
	return nil
}

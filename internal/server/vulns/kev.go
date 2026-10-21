package vulns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// MaxFeedBytes bounds a downloaded or uploaded feed body.
const MaxFeedBytes = 64 << 20

var cveRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// KEVEntry is one vulnerability of the CISA catalog of known exploited vulnerabilities.
type KEVEntry struct {
	CVE        string
	Name       string
	Added      *time.Time
	Due        *time.Time
	Ransomware bool
	Action     string
}

// kevFile is the catalog's JSON (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
type kevFile struct {
	Title    string `json:"title"`
	Version  string `json:"catalogVersion"`
	Released string `json:"dateReleased"`
	Count    int    `json:"count"`
	Vulns    []struct {
		CVE        string `json:"cveID"`
		Vendor     string `json:"vendorProject"`
		Product    string `json:"product"`
		Name       string `json:"vulnerabilityName"`
		Added      string `json:"dateAdded"`
		Summary    string `json:"shortDescription"`
		Action     string `json:"requiredAction"`
		Due        string `json:"dueDate"`
		Ransomware string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

func day(s string) *time.Time {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return &t
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n])
	}
	return string(r)
}

// ParseKEV reads the CISA catalog. Entries with a malformed CVE id are skipped; a file with no vulnerabilities at all is
// refused, because an empty catalog would clear every exploited mark.
func ParseKEV(raw []byte) ([]KEVEntry, error) {
	if len(raw) > MaxFeedBytes {
		return nil, fmt.Errorf("the catalog is larger than %d bytes", MaxFeedBytes)
	}
	var f kevFile
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&f); err != nil {
		return nil, fmt.Errorf("not a CISA catalog: %w", err)
	}
	var out []KEVEntry
	seen := map[string]bool{}
	for _, v := range f.Vulns {
		id := strings.ToUpper(strings.TrimSpace(v.CVE))
		if !cveRe.MatchString(id) || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, KEVEntry{CVE: id, Name: clip(v.Name, 300), Added: day(v.Added), Due: day(v.Due), Ransomware: strings.EqualFold(strings.TrimSpace(v.Ransomware), "known"), Action: clip(v.Action, 500)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the catalog has no vulnerabilities in it")
	}
	return out, nil
}

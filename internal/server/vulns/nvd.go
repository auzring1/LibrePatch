package vulns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Range is one set of versions of a product that a CVE affects.
type Range struct {
	Vendor, Product string
	StartKey        []byte // nil: from the first version
	StartIncl       bool
	StartText       string
	EndKey          []byte // nil: to the last version
	EndIncl         bool
	EndText         string
}

// CVE is what the NVD says about one vulnerability.
type CVE struct {
	ID        string
	Published *time.Time
	Modified  *time.Time
	Summary   string
	CVSS      *float32
	Severity  string // low, medium, high, critical, or ""
	Ranges    []Range
	Rejected  bool
}

// Tracked says which (vendor, product) pairs the caller wants ranges for; nil keeps every pair.
type Tracked map[[2]string]bool

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // CVSS 2 keeps it beside cvssData
}

type nvdMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}

type nvdNode struct {
	Match    []nvdMatch `json:"cpeMatch"`
	Children []nvdNode  `json:"children"`
}

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			VulnStatus   string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V40 []nvdMetric `json:"cvssMetricV40"`
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []nvdNode `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Page is one response of the NVD API.
type Page struct {
	CVEs         []CVE
	StartIndex   int
	PerPage      int
	TotalResults int
}

func nvdTime(s string) *time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func rangeFor(m nvdMatch, tracked Tracked) (Range, bool) {
	if !m.Vulnerable {
		return Range{}, false
	}
	c, err := ParseCPE23(m.Criteria)
	if err != nil || (c.Part != "a" && c.Part != "o") {
		return Range{}, false
	}
	if tracked != nil && !tracked[[2]string{c.Vendor, c.Product}] {
		return Range{}, false
	}
	r := Range{Vendor: c.Vendor, Product: c.Product}
	set := func(text string) ([]byte, bool) {
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, true
		}
		k := vercmp.Key(text)
		return k, k != nil
	}
	hasBound := m.StartIncluding != "" || m.StartExcluding != "" || m.EndIncluding != "" || m.EndExcluding != ""
	switch {
	case hasBound:
		var ok bool
		switch {
		case m.StartIncluding != "":
			r.StartKey, ok = set(m.StartIncluding)
			r.StartIncl, r.StartText = true, m.StartIncluding
		case m.StartExcluding != "":
			r.StartKey, ok = set(m.StartExcluding)
			r.StartText = m.StartExcluding
		default:
			ok = true
		}
		if !ok {
			return Range{}, false
		}
		switch {
		case m.EndExcluding != "":
			r.EndKey, ok = set(m.EndExcluding)
			r.EndText = m.EndExcluding
		case m.EndIncluding != "":
			r.EndKey, ok = set(m.EndIncluding)
			r.EndIncl, r.EndText = true, m.EndIncluding
		default:
			ok = true
		}
		if !ok {
			return Range{}, false
		}
	case !c.Any():
		// One exact version.
		k := vercmp.Key(c.Version)
		if k == nil {
			return Range{}, false
		}
		r.StartKey, r.StartIncl, r.StartText = k, true, c.Version
		r.EndKey, r.EndIncl, r.EndText = k, true, c.Version
	}
	return r, true
}

func collect(nodes []nvdNode, tracked Tracked, out *[]Range) {
	for _, n := range nodes {
		for _, m := range n.Match {
			if r, ok := rangeFor(m, tracked); ok {
				*out = append(*out, r)
			}
		}
		collect(n.Children, tracked, out)
	}
}

func bestMetric(ms ...[]nvdMetric) (*float32, string) {
	for _, list := range ms {
		if len(list) == 0 {
			continue
		}
		m := list[0]
		sev := strings.ToLower(m.CVSSData.BaseSeverity)
		if sev == "" {
			sev = strings.ToLower(m.BaseSeverity)
		}
		switch sev {
		case "low", "medium", "high", "critical":
		default:
			sev = ""
		}
		s := float32(m.CVSSData.BaseScore)
		return &s, sev
	}
	return nil, ""
}

// ParseNVD reads one page of the NVD CVE API 2.0 (the body of a response to /rest/json/cves/2.0). Only the version
// ranges of the tracked products are kept. A CVE the NVD has rejected is returned with Rejected set, so the caller can drop
// what it stored before.
func ParseNVD(raw []byte, tracked Tracked) (*Page, error) {
	if len(raw) > MaxFeedBytes {
		return nil, fmt.Errorf("the response is larger than %d bytes", MaxFeedBytes)
	}
	var r nvdResponse
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&r); err != nil {
		return nil, fmt.Errorf("not an NVD response: %w", err)
	}
	if r.Vulnerabilities == nil && r.TotalResults == 0 && r.ResultsPerPage == 0 {
		return nil, fmt.Errorf("not an NVD response: no vulnerabilities list")
	}
	p := &Page{StartIndex: r.StartIndex, PerPage: r.ResultsPerPage, TotalResults: r.TotalResults}
	for _, v := range r.Vulnerabilities {
		c := v.CVE
		id := strings.ToUpper(strings.TrimSpace(c.ID))
		if !cveRe.MatchString(id) {
			continue
		}
		out := CVE{ID: id, Published: nvdTime(c.Published), Modified: nvdTime(c.LastModified), Rejected: strings.EqualFold(c.VulnStatus, "Rejected")}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				out.Summary = clip(d.Value, 600)
				break
			}
		}
		out.CVSS, out.Severity = bestMetric(c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2)
		for _, cfg := range c.Configurations {
			collect(cfg.Nodes, tracked, &out.Ranges)
		}
		p.CVEs = append(p.CVEs, out)
	}
	return p, nil
}

package vulns

import (
	"sort"
	"strings"
)

func rank(sev string) int {
	switch sev {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func sortHits(h []DeviceHit) {
	sort.SliceStable(h, func(i, j int) bool {
		return strings.ToLower(h[i].Hostname) < strings.ToLower(h[j].Hostname)
	})
}

// sortDeviceItems puts the exploited ones first, then by severity and score.
func sortDeviceItems(items []DeviceItem) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if ra, rb := rank(a.Severity), rank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.CVSS != nil && b.CVSS != nil && *a.CVSS != *b.CVSS {
			return *a.CVSS > *b.CVSS
		}
		return a.ID < b.ID
	})
}

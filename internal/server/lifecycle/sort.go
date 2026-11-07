package lifecycle

import (
	"sort"
	"strings"
)

// sortRows puts the devices that are out of support, or closest to it, first.
func sortRows(rows []Row) {
	rank := func(r Row) int {
		switch r.Status {
		case Unsupported:
			return 0
		case EndingSoon:
			return 1
		case Unknown:
			return 3
		}
		return 2
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra < rb
		}
		if a.DaysLeft != nil && b.DaysLeft != nil && *a.DaysLeft != *b.DaysLeft {
			return *a.DaysLeft < *b.DaysLeft
		}
		return strings.ToLower(a.Hostname) < strings.ToLower(b.Hostname)
	})
}

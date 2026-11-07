// Package lifecycle tells which devices run an operating system that Microsoft no longer supports, or soon will not.
//
// The end-of-support dates are a built-in table, not a lookup on the internet: the server never phones home (O9), and
// the dates change only a few times a year. The table is reviewed at each release; DataAsOf says when it was last
// checked. The dates were taken from secondary sources and have not been compared with Microsoft's own lifecycle pages,
// so they are a guide for planning, not a contract. A device whose operating system the table does not know is reported
// as "unknown", never as supported.
package lifecycle

import (
	"strconv"
	"strings"
	"time"
)

// DataAsOf is when the table below was last reviewed.
const DataAsOf = "2026-10-19"

// DefaultWarnDays is how long before the end of support a device is flagged as "ending soon".
const DefaultWarnDays = 180

// Status of a device's operating system.
const (
	Supported   = "supported"
	EndingSoon  = "ending_soon"
	Unsupported = "unsupported"
	Unknown     = "unknown"
)

// Info is the lifecycle of one operating system release.
type Info struct {
	Product string // "Windows 11", "Windows Server 2022"
	Release string // "24H2"; empty for a server release
	End     *time.Time
	Status  string
	// DaysLeft is negative once support has ended; nil when the end date is not known.
	DaysLeft *int
	Note     string
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// release is one row of the table. Consumer is the end for Home and Pro (24 months of servicing), Business for
// Enterprise, Education and IoT Enterprise (36 months). A release that has no separate dates sets both the same.
type release struct {
	build    int
	product  string
	name     string
	consumer time.Time
	business time.Time
}

var client = []release{
	{19045, "Windows 10", "22H2", day(2025, 10, 14), day(2025, 10, 14)},
	{22000, "Windows 11", "21H2", day(2023, 10, 10), day(2024, 10, 8)},
	{22621, "Windows 11", "22H2", day(2024, 10, 8), day(2025, 10, 14)},
	{22631, "Windows 11", "23H2", day(2025, 11, 11), day(2026, 11, 10)},
	{26100, "Windows 11", "24H2", day(2026, 10, 13), day(2027, 10, 12)},
	{26200, "Windows 11", "25H2", day(2027, 10, 12), day(2028, 10, 10)},
	{26300, "Windows 11", "26H2", day(2028, 10, 10), day(2029, 10, 9)},
}

// ltsc lists the long-term servicing releases, which run on their own builds. iot is the date for the IoT Enterprise
// edition of the same release where it differs.
var ltsc = []struct {
	build   int
	product string
	name    string
	end     time.Time
	iot     time.Time
}{
	{10240, "Windows 10 Enterprise LTSB", "2015", day(2025, 10, 14), day(2025, 10, 14)},
	{14393, "Windows 10 Enterprise LTSB", "2016", day(2026, 10, 13), day(2026, 10, 13)},
	{17763, "Windows 10 Enterprise LTSC", "2019", day(2029, 1, 9), day(2029, 1, 9)},
	{19044, "Windows 10 Enterprise LTSC", "2021", day(2027, 1, 12), day(2032, 1, 13)},
	{26100, "Windows 11 Enterprise LTSC", "2024", day(2029, 10, 9), day(2034, 10, 10)},
}

var servers = []struct {
	build   int
	product string
	end     time.Time
}{
	{14393, "Windows Server 2016", day(2027, 1, 12)},
	{17763, "Windows Server 2019", day(2029, 1, 9)},
	{20348, "Windows Server 2022", day(2031, 10, 14)},
	{26100, "Windows Server 2025", day(2034, 11, 14)},
}

const (
	noteESU    = "Paid Extended Security Updates may still cover this device; this server cannot tell."
	noteEdtn   = "The edition is not known, so the earlier (Home and Pro) date is used."
	noteTable  = "This operating system is newer than the table in this version of the server."
	noteOldest = "Older than any release in the table."
)

func end(t time.Time) *time.Time { return &t }

func (i *Info) classify(now time.Time, warnDays int) {
	if i.End == nil {
		return
	}
	days := int(i.End.Sub(now.UTC().Truncate(24*time.Hour)).Hours() / 24)
	i.DaysLeft = &days
	switch {
	case days < 0:
		i.Status = Unsupported
	case days <= warnDays:
		i.Status = EndingSoon
	default:
		i.Status = Supported
	}
	if i.Status == Unsupported && i.Note == "" {
		i.Note = noteESU
	}
}

// Lookup finds the lifecycle of an operating system from what the agent reports: the product name ("Windows 11 Pro",
// "Windows Server 2022 Standard"), the build number (26100) and the edition id ("Professional", "EnterpriseS").
// warnDays is how many days before the end a device counts as "ending soon" (0 uses DefaultWarnDays).
func Lookup(caption, edition string, build int, now time.Time, warnDays int) Info {
	if warnDays <= 0 {
		warnDays = DefaultWarnDays
	}
	var out Info
	switch {
	case !strings.HasPrefix(strings.ToLower(strings.TrimSpace(caption)), "windows"):
		return Info{Status: Unknown, Note: "Not a Windows device."}
	case build <= 0:
		return Info{Status: Unknown, Note: "The build number has not been reported yet."}
	case strings.Contains(strings.ToLower(caption), "server"):
		out = lookupServer(build)
	case isLTSC(edition):
		out = lookupLTSC(build, edition)
	default:
		out = lookupClient(build, edition)
	}
	out.classify(now, warnDays)
	if out.End == nil && out.Status == "" {
		out.Status = Unknown
	}
	return out
}

func isLTSC(edition string) bool {
	e := strings.ToLower(edition)
	return strings.HasSuffix(e, "enterprises") || strings.HasSuffix(e, "enterprisesn")
}

func isIoT(edition string) bool { return strings.HasPrefix(strings.ToLower(edition), "iot") }

// business is true for Enterprise, Education and IoT Enterprise, which are serviced for 36 months.
func business(edition string) (isBusiness, known bool) {
	e := strings.ToLower(edition)
	switch {
	case e == "":
		return false, false
	case strings.HasPrefix(e, "core"), strings.HasPrefix(e, "professional"):
		return false, true
	case strings.HasPrefix(e, "enterprise"), strings.HasPrefix(e, "education"), strings.HasPrefix(e, "iotenterprise"):
		return true, true
	}
	return false, false
}

func lookupClient(build int, edition string) Info {
	for _, r := range client {
		if r.build != build {
			continue
		}
		b, known := business(edition)
		when, note := r.consumer, ""
		if b {
			when = r.business
		} else if !known {
			note = noteEdtn
		}
		return Info{Product: r.product, Release: r.name, End: end(when), Note: note}
	}
	switch {
	case build < client[0].build:
		return Info{Product: "Windows", Release: "build " + strconv.Itoa(build), Status: Unsupported, Note: noteOldest}
	case build > client[len(client)-1].build:
		return Info{Product: "Windows 11", Release: "build " + strconv.Itoa(build), Status: Unknown, Note: noteTable}
	}
	return Info{Product: "Windows", Release: "build " + strconv.Itoa(build), Status: Unknown, Note: "This build is not in the table."}
}

func lookupLTSC(build int, edition string) Info {
	for _, r := range ltsc {
		if r.build == build {
			when := r.end
			if isIoT(edition) {
				when = r.iot
			}
			return Info{Product: r.product, Release: r.name, End: end(when)}
		}
	}
	return Info{Product: "Windows (long-term servicing)", Release: "build " + strconv.Itoa(build), Status: Unknown, Note: "This long-term servicing build is not in the table."}
}

func lookupServer(build int) Info {
	for _, s := range servers {
		if s.build == build {
			return Info{Product: s.product, End: end(s.end)}
		}
	}
	switch {
	case build < servers[0].build:
		return Info{Product: "Windows Server", Release: "build " + strconv.Itoa(build), Status: Unsupported, Note: "Older than Windows Server 2016. " + noteESU}
	case build > servers[len(servers)-1].build:
		return Info{Product: "Windows Server", Release: "build " + strconv.Itoa(build), Status: Unknown, Note: noteTable}
	}
	return Info{Product: "Windows Server", Release: "build " + strconv.Itoa(build), Status: Unknown, Note: "This build is not in the table (a semi-annual channel release?)."}
}

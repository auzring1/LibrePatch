package lifecycle

import (
	"strings"
	"testing"
	"time"
)

var today = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func TestLookup(t *testing.T) {
	cases := []struct {
		name            string
		caption, edtn   string
		build           int
		status, product string
		release         string
		end             string
		note            string // a fragment the note must contain
	}{
		{"Windows 11 24H2 Pro is out of support (13 Oct 2026)", "Windows 11 Pro", "Professional", 26100, Unsupported, "Windows 11", "24H2", "2026-10-13", "Extended Security"},
		{"Windows 11 24H2 Enterprise has a year", "Windows 11 Enterprise", "Enterprise", 26100, Supported, "Windows 11", "24H2", "2027-10-12", ""},
		{"Windows 11 23H2 Enterprise ends in a month", "Windows 11 Enterprise", "Enterprise", 22631, EndingSoon, "Windows 11", "23H2", "2026-11-10", ""},
		{"Windows 11 25H2 Home", "Windows 11 Home", "Core", 26200, Supported, "Windows 11", "25H2", "2027-10-12", ""},
		{"Windows 11 26H2 Pro ends in 2028", "Windows 11 Pro", "Professional", 26300, Supported, "Windows 11", "26H2", "2028-10-10", ""},
		{"Windows 11 26H2 Enterprise ends in 2029", "Windows 11 Enterprise", "Enterprise", 26300, Supported, "Windows 11", "26H2", "2029-10-09", ""},
		{"Windows 10 22H2 is out of support", "Windows 10 Pro", "Professional", 19045, Unsupported, "Windows 10", "22H2", "2025-10-14", "Extended Security"},
		{"An older Windows 10 build", "Windows 10 Pro", "Professional", 19043, Unsupported, "Windows", "build 19043", "", "Older than"},
		{"Windows 8.1", "Windows 8.1 Pro", "Professional", 9600, Unsupported, "Windows", "build 9600", "", "Older than"},
		{"Server 2025 shares a build with Windows 11 24H2", "Windows Server 2025 Standard", "ServerStandard", 26100, Supported, "Windows Server 2025", "", "2034-11-14", ""},
		{"Server 2016 is in its last months", "Windows Server 2016 Standard", "ServerStandard", 14393, EndingSoon, "Windows Server 2016", "", "2027-01-12", ""},
		{"Server 2019", "Windows Server 2019 Datacenter", "ServerDatacenter", 17763, Supported, "Windows Server 2019", "", "2029-01-09", ""},
		{"Server 2012 R2", "Windows Server 2012 R2 Standard", "ServerStandard", 9600, Unsupported, "Windows Server", "build 9600", "", "Older than Windows Server 2016"},
		{"LTSC 2021 ends in under three months", "Windows 10 Enterprise LTSC", "EnterpriseS", 19044, EndingSoon, "Windows 10 Enterprise LTSC", "2021", "2027-01-12", ""},
		{"IoT LTSC 2021 lasts longer", "Windows 10 IoT Enterprise LTSC", "IoTEnterpriseS", 19044, Supported, "Windows 10 Enterprise LTSC", "2021", "2032-01-13", ""},
		{"An unknown edition uses the earlier date and says so", "Windows 11", "", 26100, Unsupported, "Windows 11", "24H2", "2026-10-13", "edition is not known"},
		{"A build newer than the table is unknown, not supported", "Windows 11 Pro", "Professional", 30000, Unknown, "Windows 11", "build 30000", "", "newer than the table"},
		{"A build the table does not know", "Windows 11 Pro", "Professional", 22500, Unknown, "Windows", "build 22500", "", "not in the table"},
		{"Not Windows", "Ubuntu 24.04", "", 0, Unknown, "", "", "", "Not a Windows device"},
		{"No build yet", "Windows 11 Pro", "Professional", 0, Unknown, "", "", "", "not been reported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Lookup(c.caption, c.edtn, c.build, today, 0)
			if got.Status != c.status {
				t.Errorf("status %q, want %q (%+v)", got.Status, c.status, got)
			}
			if got.Product != c.product || got.Release != c.release {
				t.Errorf("product/release %q/%q, want %q/%q", got.Product, got.Release, c.product, c.release)
			}
			if c.end == "" {
				if got.End != nil {
					t.Errorf("end %v, want none", got.End)
				}
			} else if got.End == nil || got.End.Format("2006-01-02") != c.end {
				t.Errorf("end %v, want %s", got.End, c.end)
			}
			if c.note != "" && !strings.Contains(got.Note, c.note) {
				t.Errorf("note %q lacks %q", got.Note, c.note)
			}
			if c.note == "" && c.status != Unknown && got.Note != "" {
				t.Errorf("unexpected note %q", got.Note)
			}
		})
	}
}

func TestSupportEndsAfterTheLastDay(t *testing.T) {
	// On the end date itself Windows still gets its last updates; the day after, it is out of support.
	onTheDay := time.Date(2026, 10, 13, 23, 0, 0, 0, time.UTC)
	if got := Lookup("Windows 11 Pro", "Professional", 26100, onTheDay, 0); got.Status != EndingSoon || *got.DaysLeft != 0 {
		t.Fatalf("on the last day: %+v", got)
	}
	next := time.Date(2026, 10, 14, 0, 30, 0, 0, time.UTC)
	if got := Lookup("Windows 11 Pro", "Professional", 26100, next, 0); got.Status != Unsupported || *got.DaysLeft != -1 {
		t.Fatalf("the day after: %+v", got)
	}
}

func TestWarnWindow(t *testing.T) {
	// 23H2 Enterprise ends in 22 days: ending soon with a 30-day window, supported with a 10-day window.
	if got := Lookup("Windows 11 Enterprise", "Enterprise", 22631, today, 30); got.Status != EndingSoon {
		t.Fatalf("30-day window: %+v", got)
	}
	if got := Lookup("Windows 11 Enterprise", "Enterprise", 22631, today, 10); got.Status != Supported {
		t.Fatalf("10-day window: %+v", got)
	}
}

func TestSortPutsTheWorstFirst(t *testing.T) {
	mk := func(host, status string, days *int) Row {
		return Row{Hostname: host, Info: Info{Status: status, DaysLeft: days}}
	}
	d := func(n int) *int { return &n }
	rows := []Row{mk("zeta", Supported, d(900)), mk("alpha", Unknown, nil), mk("mid", EndingSoon, d(20)), mk("old", Unsupported, d(-300)), mk("older", Unsupported, d(-10)), mk("soon", EndingSoon, d(5))}
	sortRows(rows)
	var got []string
	for _, r := range rows {
		got = append(got, r.Hostname)
	}
	if strings.Join(got, ",") != "old,older,soon,mid,zeta,alpha" {
		t.Fatalf("order: %v", got)
	}
	if s := Summarize(rows); s.Unsupported != 2 || s.EndingSoon != 2 || s.Supported != 1 || s.Unknown != 1 {
		t.Fatalf("summary: %+v", s)
	}
}

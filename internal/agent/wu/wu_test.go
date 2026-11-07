package wu

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func TestActiveHours(t *testing.T) {
	loc := time.UTC
	at := func(h, m int) time.Time { return time.Date(2026, 3, 10, h, m, 0, 0, loc) }
	day := &agentv1.ActiveHours{StartMinute: 8 * 60, EndMinute: 17 * 60}
	night := &agentv1.ActiveHours{StartMinute: 22 * 60, EndMinute: 6 * 60} // wraps midnight
	cases := []struct {
		ah   *agentv1.ActiveHours
		t    time.Time
		want bool
	}{
		{day, at(7, 59), false}, {day, at(8, 0), true}, {day, at(16, 59), true}, {day, at(17, 0), false},
		{night, at(23, 0), true}, {night, at(5, 59), true}, {night, at(6, 0), false}, {night, at(12, 0), false},
		{nil, at(10, 0), false}, {&agentv1.ActiveHours{StartMinute: 5, EndMinute: 5}, at(10, 0), false},
	}
	for i, c := range cases {
		if got := InActiveHours(c.ah, c.t, loc); got != c.want {
			t.Errorf("case %d: InActiveHours(%v) = %v, want %v", i, c.t.Format("15:04"), got, c.want)
		}
	}
	if got := NextOutsideActiveHours(day, at(10, 30), loc); !got.Equal(at(17, 0)) {
		t.Errorf("next outside during the day: %v", got)
	}
	if got := NextOutsideActiveHours(day, at(18, 0), loc); !got.Equal(at(18, 0)) {
		t.Errorf("already outside: %v", got)
	}
	// Active hours that end after midnight: from 23:30 the next free moment is 06:00 the next day.
	if got := NextOutsideActiveHours(night, at(23, 30), loc); !got.Equal(at(6, 0).AddDate(0, 0, 1)) {
		t.Errorf("wrapping range: %v", got)
	}
	if got := NextOutsideActiveHours(night, at(2, 0), loc); !got.Equal(at(6, 0)) {
		t.Errorf("after midnight: %v", got)
	}
}

func TestSnapshotTruncatesAndCarriesErrors(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var ups []*agentv1.WuUpdate
	for i := 0; i < MaxUpdates+5; i++ {
		ups = append(ups, &agentv1.WuUpdate{UpdateId: "u"})
	}
	s := Snapshot(ups, nil, true, Options{Service: agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE}, nil, now)
	if len(s.Updates) != MaxUpdates || !s.Truncated || !s.RebootRequired || s.ScannedAt != now.Unix() || s.Service != int32(agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE) {
		t.Fatalf("%+v", s)
	}
	s = Snapshot(ups, nil, false, Options{}, errors.New("0x80072ee2 no network"), now)
	if len(s.Updates) != 0 || s.ScanError == "" {
		t.Fatalf("a failed scan must report the error and no updates: %+v", s)
	}
}

package jobs

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

// Read-only views of a device (D125): running programs, services and recent event log entries. Nothing here changes
// anything on the computer.

// Limits of the views.
const (
	MaxInspectBytes   = 256 << 10
	maxInspectItems   = 5000
	maxEventsPerQuery = 200
	maxEventMessage   = 600
)

// ProcessInfo is one running program.
type ProcessInfo struct {
	PID          uint32 `json:"pid"`
	ParentPID    uint32 `json:"parent_pid"`
	Name         string `json:"name"`
	Session      uint32 `json:"session"`
	Threads      uint32 `json:"threads"`
	WorkingSetKB uint64 `json:"working_set_kb"`
	Path         string `json:"path,omitempty"`
}

// ServiceInfo is one Windows service.
type ServiceInfo struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	State   string `json:"state"`   // running | stopped | starting | stopping | paused | ...
	Start   string `json:"start"`   // automatic | automatic_delayed | manual | disabled | boot | system
	Account string `json:"account"` // the account it runs as
	Path    string `json:"path"`
}

// EventInfo is one event log entry.
type EventInfo struct {
	Time     int64  `json:"time"` // unix seconds
	Level    int    `json:"level"`
	Provider string `json:"provider"`
	ID       uint32 `json:"id"`
	Message  string `json:"message"`
}

// EventQuery is what the event view asks the platform for.
type EventQuery struct {
	Log      string
	MaxLevel int
	Since    time.Duration
	Max      int
}

var inspectLogs = map[string]bool{"System": true, "Application": true, "Setup": true}

// ValidateInspect checks an inspect job body. The Security log is never offered: it records who signed in and what they did.
func ValidateInspect(b *agentv1.InspectBody) error {
	if b == nil {
		return bad("missing body")
	}
	switch b.Kind {
	case agentv1.InspectKind_INSPECT_KIND_PROCESSES, agentv1.InspectKind_INSPECT_KIND_SERVICES:
	case agentv1.InspectKind_INSPECT_KIND_EVENTS:
		if b.Log != "" && !inspectLogs[b.Log] {
			return bad("the event log must be System, Application or Setup")
		}
		if b.MaxLevel > 5 || b.SinceMinutes > 10080 || b.MaxEvents > maxEventsPerQuery {
			return bad("event view limits exceeded")
		}
	default:
		return bad("unknown view")
	}
	return nil
}

type inspectDoc struct {
	Kind      string          `json:"kind"`
	TakenAt   int64           `json:"taken_at"`
	Truncated bool            `json:"truncated"`
	Total     int             `json:"total"`
	Items     json.RawMessage `json:"items"`
}

// encodeView marshals the items, dropping from the end until the document fits.
func encodeView[T any](kind string, now time.Time, items []T) (string, bool, error) {
	total := len(items)
	if len(items) > maxInspectItems {
		items = items[:maxInspectItems]
	}
	for {
		raw, err := json.Marshal(items)
		if err != nil {
			return "", false, err
		}
		doc, err := json.Marshal(inspectDoc{Kind: kind, TakenAt: now.Unix(), Truncated: len(items) < total, Total: total, Items: raw})
		if err != nil {
			return "", false, err
		}
		if len(doc) <= MaxInspectBytes || len(items) == 0 {
			return string(doc), len(items) < total, nil
		}
		items = items[:len(items)*3/4]
	}
}

func (e *Engine) inspect(ctx context.Context, env *agentv1.JobEnvelope) *outcome {
	b := env.GetInspect()
	var data string
	var cut bool
	var err error
	now := e.now()
	switch b.Kind {
	case agentv1.InspectKind_INSPECT_KIND_PROCESSES:
		var ps []ProcessInfo
		if ps, err = e.P.Processes(); err == nil {
			sort.Slice(ps, func(i, j int) bool {
				if li, lj := strings.ToLower(ps[i].Name), strings.ToLower(ps[j].Name); li != lj {
					return li < lj
				}
				return ps[i].PID < ps[j].PID
			})
			data, cut, err = encodeView("processes", now, ps)
		}
	case agentv1.InspectKind_INSPECT_KIND_SERVICES:
		var ss []ServiceInfo
		if ss, err = e.P.Services(); err == nil {
			sort.Slice(ss, func(i, j int) bool { return strings.ToLower(ss[i].Display) < strings.ToLower(ss[j].Display) })
			data, cut, err = encodeView("services", now, ss)
		}
	case agentv1.InspectKind_INSPECT_KIND_EVENTS:
		q := EventQuery{Log: b.Log, MaxLevel: int(b.MaxLevel), Since: time.Duration(b.SinceMinutes) * time.Minute, Max: int(b.MaxEvents)}
		if q.Log == "" {
			q.Log = "System"
		}
		if q.MaxLevel == 0 {
			q.MaxLevel = 3
		}
		if q.Since == 0 {
			q.Since = 24 * time.Hour
		}
		if q.Max == 0 {
			q.Max = 100
		}
		var evs []EventInfo
		if evs, err = e.P.Events(ctx, q); err == nil {
			for i := range evs {
				evs[i].Message = clipText(evs[i].Message, maxEventMessage)
			}
			data, cut, err = encodeView("events", now, evs)
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return &outcome{res: &agentv1.JobResult{}, cancelled: true}
		}
		if errors.Is(err, ErrUnsupported) {
			return fail("this computer cannot show that view")
		}
		return fail("could not read it: %v", err)
	}
	msg := "view read"
	if cut {
		msg += " (shortened to fit)"
	}
	return &outcome{res: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true, Message: msg, DataJson: data}}
}

func clipText(s string, n int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "�")
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { // do not cut a character in half
		n--
	}
	return s[:n] + "…"
}

// ParseEventXML reads the output of `wevtutil qe <log> /f:RenderedXml`: Event elements one after the other, with no root.
func ParseEventXML(r io.Reader, max int) ([]EventInfo, error) {
	type data struct {
		Name string `xml:"Name,attr"`
		Text string `xml:",chardata"`
	}
	type event struct {
		System struct {
			Provider struct {
				Name string `xml:"Name,attr"`
			} `xml:"Provider"`
			EventID     string `xml:"EventID"`
			Level       string `xml:"Level"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
		} `xml:"System"`
		EventData     struct{ Data []data } `xml:"EventData"`
		RenderingInfo struct {
			Message string `xml:"Message"`
			Level   string `xml:"Level"`
		} `xml:"RenderingInfo"`
	}
	dec := xml.NewDecoder(io.LimitReader(r, 16<<20))
	dec.Strict = false
	var out []EventInfo
	for len(out) < max {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev event
		if err := dec.DecodeElement(&ev, &se); err != nil {
			return out, err
		}
		t, _ := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
		id, _ := strconv.ParseUint(strings.TrimSpace(ev.System.EventID), 10, 32)
		lvl, _ := strconv.Atoi(strings.TrimSpace(ev.System.Level))
		msg := strings.TrimSpace(ev.RenderingInfo.Message)
		if msg == "" {
			var parts []string
			for _, d := range ev.EventData.Data {
				if v := strings.TrimSpace(d.Text); v != "" {
					parts = append(parts, v)
				}
			}
			msg = strings.Join(parts, " | ")
		}
		out = append(out, EventInfo{Time: t.Unix(), Level: lvl, Provider: ev.System.Provider.Name, ID: uint32(id), Message: msg}) // #nosec G115 -- ParseUint bitSize 32
	}
	return out, nil
}

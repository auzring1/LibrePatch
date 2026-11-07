package updates

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/text"
)

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	kbRe   = regexp.MustCompile(`^[0-9A-Za-z]{1,16}$`)
)

var stateName = map[agentv1.WuUpdateState]string{
	agentv1.WuUpdateState_WU_UPDATE_STATE_MISSING:        "missing",
	agentv1.WuUpdateState_WU_UPDATE_STATE_DOWNLOADED:     "downloaded",
	agentv1.WuUpdateState_WU_UPDATE_STATE_HIDDEN:         "hidden",
	agentv1.WuUpdateState_WU_UPDATE_STATE_PENDING_REBOOT: "pending_reboot",
	agentv1.WuUpdateState_WU_UPDATE_STATE_FAILED:         "failed",
}

var severities = map[string]bool{"": true, "Critical": true, "Important": true, "Moderate": true, "Low": true}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == 0 || r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	return text.Truncate(s, n)
}

// webURL keeps an http(s) address and drops anything else. The text comes from the endpoint, which may be compromised,
// and the console shows it as a link: a "javascript:" or "data:" address must never be stored.
func webURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return s
}

type policyJSON struct {
	WSUSConfigured    bool     `json:"wsus_configured"`
	WSUSServer        string   `json:"wsus_server,omitempty"`
	WUfBDeferrals     bool     `json:"wufb_deferrals"`
	NoAutoUpdate      bool     `json:"no_auto_update"`
	AUOptions         uint32   `json:"au_options,omitempty"`
	ActiveHoursPolicy bool     `json:"active_hours_policy"`
	WUServiceDisabled bool     `json:"wu_service_disabled"`
	EffectiveSource   string   `json:"effective_source"`
	Notes             []string `json:"notes,omitempty"`
}

func policyOf(p *agentv1.WuPolicyInfo) *policyJSON {
	if p == nil {
		return nil
	}
	out := &policyJSON{WSUSConfigured: p.WsusConfigured, WSUSServer: clean(p.WsusServer, 256), WUfBDeferrals: p.WufbDeferrals, NoAutoUpdate: p.NoAutoUpdate,
		AUOptions: p.AuOptions, ActiveHoursPolicy: p.ActiveHoursPolicy, WUServiceDisabled: p.WuServiceDisabled}
	switch p.EffectiveSource {
	case "windows_update", "microsoft_update", "wsus":
		out.EffectiveSource = p.EffectiveSource
	}
	for i, n := range p.Notes {
		if i >= 8 {
			break
		}
		out.Notes = append(out.Notes, clean(n, 256))
	}
	return out
}

// ApplySnapshot validates a device's Windows Update snapshot and replaces what the server knows
// about that device's updates. Agent-supplied data is untrusted: every field is bounded and checked.
func (s *Service) ApplySnapshot(ctx context.Context, dev dbq.Device, rev uint64, snap *agentv1.WuInventory) error {
	if snap == nil {
		return invalid("empty snapshot")
	}
	if !s.On(ctx, dev.OrgID) {
		return nil // Windows updates are switched off for this organization: the report is acknowledged and dropped
	}
	if len(snap.Updates) > maxUpdatesPerSnapshot {
		return invalid("too many updates")
	}
	scanned := time.Unix(snap.ScannedAt, 0)
	now := s.now()
	if snap.ScannedAt <= 0 || scanned.After(now.Add(10*time.Minute)) {
		scanned = now // a wrong device clock must not place the scan in the future
	}
	seen := map[string]bool{}
	var (
		ids                               []uuid.UUID
		revs                              []int32
		titles, kbs, classes, sevs, prods []string
		drivers                           []bool
		dclass, dhwid, dver, urls         []string
		release, sizes                    []int64
		reboots                           []bool
		dIDs                              []uuid.UUID
		dRevs                             []int32
		dStates, dErrs                    []string
	)
	for _, u := range snap.Updates {
		if !uuidRe.MatchString(u.UpdateId) || u.Revision < 0 || len(u.Title) == 0 {
			return invalid("malformed update entry")
		}
		id, err := uuid.Parse(strings.ToLower(u.UpdateId))
		if err != nil || seen[id.String()] {
			continue
		}
		seen[id.String()] = true
		state, ok := stateName[u.State]
		if !ok {
			return invalid("unknown update state")
		}
		if !severities[u.Severity] || len(u.Kb) > 16 || len(u.Products) > 16 {
			return invalid("update fields out of range")
		}
		for _, k := range u.Kb {
			if !kbRe.MatchString(strings.TrimPrefix(strings.ToUpper(k), "KB")) {
				return invalid("malformed KB number")
			}
		}
		ids, revs = append(ids, id), append(revs, u.Revision)
		titles = append(titles, clean(u.Title, 512))
		kbs = append(kbs, strings.Join(u.Kb, ","))
		classes = append(classes, clean(u.Classification, 128))
		sevs = append(sevs, u.Severity)
		prods = append(prods, clean(strings.Join(u.Products, "|"), 1024))
		drivers = append(drivers, u.IsDriver)
		dclass, dhwid, dver = append(dclass, clean(u.DriverClass, 128)), append(dhwid, clean(u.DriverHwid, 512)), append(dver, clean(u.DriverVersion, 128))
		rd := u.ReleaseDate
		if rd < 0 || rd > now.Add(24*time.Hour).Unix() {
			rd = 0
		}
		release = append(release, rd)
		urls = append(urls, webURL(clean(u.SupportUrl, 512)))
		size := int64(u.SizeBytes) // #nosec G115 -- clamped below
		if size < 0 || size > 1<<40 {
			size = 0
		}
		sizes = append(sizes, size)
		reboots = append(reboots, u.RebootRequired)
		dIDs, dRevs, dStates, dErrs = append(dIDs, id), append(dRevs, u.Revision), append(dStates, state), append(dErrs, clean(u.LastError, 128))
	}
	pol, _ := json.Marshal(policyOf(snap.Policy))
	if snap.Policy == nil {
		pol = nil
	}
	var polArg []byte = pol
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		org, err := q.LockDeviceForWU(ctx, dev.ID)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			if err := q.UpsertWuUpdates(ctx, dbq.UpsertWuUpdatesParams{OrgID: org, UpdateIds: ids, Revisions: revs, Titles: titles, Kbs: kbs,
				Classifications: classes, Severities: sevs, Products: prods, IsDrivers: drivers, DriverClasses: dclass, DriverHwids: dhwid,
				DriverVersions: dver, ReleaseUnix: release, SupportUrls: urls, Sizes: sizes, Reboots: reboots}); err != nil {
				return err
			}
		}
		if err := q.DeleteDeviceUpdates(ctx, dev.ID); err != nil {
			return err
		}
		if len(dIDs) > 0 {
			if err := q.InsertDeviceUpdates(ctx, dbq.InsertDeviceUpdatesParams{DeviceID: dev.ID, UpdateIds: dIDs, Revisions: dRevs, States: dStates,
				Errors: dErrs, ScannedAt: scanned}); err != nil {
				return err
			}
		}
		return q.SetDeviceWU(ctx, dbq.SetDeviceWUParams{ID: dev.ID, WuRev: clampRev(rev), WuScannedAt: &scanned, WuScanError: clean(snap.ScanError, 512),
			WuRebootRequired: snap.RebootRequired, WuPolicy: polArg, WuService: snap.Service, WuTruncated: snap.Truncated})
	})
	if err != nil {
		return fmt.Errorf("apply windows update snapshot: %w", err)
	}
	s.publish(dev.OrgID, dev.ID)
	return nil
}

func clampRev(r uint64) int64 {
	if r > 1<<62 {
		return 1 << 62
	}
	return int64(r) // #nosec G115 -- clamped
}

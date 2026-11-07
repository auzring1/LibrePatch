package inventory

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Limits on what an agent may report (SECURITY T-DEV-2/3).
const (
	MaxItems        = 25000
	MaxDeltaChanges = 10000
	MaxUsers        = 500
	maxName         = 512
	maxVersion      = 128
	maxPublisher    = 512
	maxPath         = 2048
	maxKey          = 512
	maxSID          = 128
)

// ErrRevMismatch means a delta's base revision differs from the server's: the
// caller must ask the agent for a full resync.
var ErrRevMismatch = errors.New("software revision mismatch")

// ErrInvalid wraps validation failures of agent-supplied data.
var ErrInvalid = errors.New("invalid inventory data")

var (
	sidRe  = regexp.MustCompile(`^S-1-\d+(-\d+)+$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// Service stores inventory reported by agents.
type Service struct {
	Pool *pgxpool.Pool
	Now  func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

var sourceNames = map[agentv1.SoftwareSource]string{
	agentv1.SoftwareSource_SOFTWARE_SOURCE_REG64:    "reg64",
	agentv1.SoftwareSource_SOFTWARE_SOURCE_REG32:    "reg32",
	agentv1.SoftwareSource_SOFTWARE_SOURCE_HKU:      "hku",
	agentv1.SoftwareSource_SOFTWARE_SOURCE_HKU32:    "hku32",
	agentv1.SoftwareSource_SOFTWARE_SOURCE_MSI:      "msi",
	agentv1.SoftwareSource_SOFTWARE_SOURCE_APPX:     "appx",
	agentv1.SoftwareSource_SOFTWARE_SOURCE_PORTABLE: "portable",
}

type keyRow struct{ source, scope, sid, key string }

type itemRow struct {
	keyRow
	name, version, publisher, installDate, location, uninstall, quiet, productCode string
	versionKey                                                                     []byte
	system                                                                         bool
	nn, np, dn, dp                                                                 string
}

// clean removes NUL bytes (PostgreSQL text cannot hold them) and bounds length.
func clean(s string, max int) (string, error) {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > max {
		return "", fmt.Errorf("%w: field longer than %d bytes", ErrInvalid, max)
	}
	return s, nil
}

func convertKey(k *agentv1.SoftwareItemKey) (keyRow, error) {
	if k == nil {
		return keyRow{}, fmt.Errorf("%w: missing item key", ErrInvalid)
	}
	src, ok := sourceNames[k.Source]
	if !ok {
		return keyRow{}, fmt.Errorf("%w: unknown source", ErrInvalid)
	}
	var scope string
	switch k.Scope {
	case agentv1.SoftwareScope_SOFTWARE_SCOPE_MACHINE:
		scope = "machine"
		if k.UserSid != "" {
			return keyRow{}, fmt.Errorf("%w: machine-scope item with a user SID", ErrInvalid)
		}
	case agentv1.SoftwareScope_SOFTWARE_SCOPE_USER:
		scope = "user"
		if len(k.UserSid) > maxSID || !sidRe.MatchString(k.UserSid) {
			return keyRow{}, fmt.Errorf("%w: bad user SID", ErrInvalid)
		}
	default:
		return keyRow{}, fmt.Errorf("%w: unknown scope", ErrInvalid)
	}
	key, err := clean(k.ItemKey, maxKey)
	if err != nil || key == "" {
		return keyRow{}, fmt.Errorf("%w: bad item key", ErrInvalid)
	}
	return keyRow{src, scope, k.UserSid, key}, nil
}

func convertItem(it *agentv1.SoftwareItem) (itemRow, error) {
	var r itemRow
	var err error
	if r.keyRow, err = convertKey(it.Key); err != nil {
		return r, err
	}
	fields := []struct {
		dst *string
		src string
		max int
	}{
		{&r.name, it.Name, maxName}, {&r.version, it.Version, maxVersion}, {&r.publisher, it.Publisher, maxPublisher},
		{&r.location, it.InstallLocation, maxPath}, {&r.uninstall, it.UninstallString, maxPath},
		{&r.quiet, it.QuietUninstallString, maxPath}, {&r.productCode, it.ProductCode, 64},
	}
	for _, f := range fields {
		if *f.dst, err = clean(f.src, f.max); err != nil {
			return r, err
		}
	}
	if strings.TrimSpace(r.name) == "" {
		return r, fmt.Errorf("%w: item without a name", ErrInvalid)
	}
	if it.InstallDate != "" {
		if !dateRe.MatchString(it.InstallDate) {
			return r, fmt.Errorf("%w: bad install date", ErrInvalid)
		}
		r.installDate = it.InstallDate
	}
	r.system = it.SystemComponent
	r.versionKey = vercmp.Key(r.version)
	r.nn, r.np = NormalizeName(r.name, r.version), NormalizePublisher(r.publisher)
	r.dn = DisplayName(r.name, r.version)
	r.dp = r.publisher
	if len(r.dp) > maxPublisher {
		r.dp = r.dp[:maxPublisher]
	}
	return r, nil
}

func convertItems(items []*agentv1.SoftwareItem) ([]itemRow, error) {
	out := make([]itemRow, 0, len(items))
	seen := make(map[keyRow]bool, len(items))
	for _, it := range items {
		r, err := convertItem(it)
		if err != nil {
			return nil, err
		}
		if seen[r.keyRow] {
			continue // duplicate key in one report: last write would win anyway
		}
		seen[r.keyRow] = true
		out = append(out, r)
	}
	return out, nil
}

// titleIDs makes sure the titles for rows exist and returns normalized key -> id.
//
// New titles are inserted in sorted key order with ON CONFLICT DO NOTHING and read back by a second
// statement. The earlier single "upsert" updated existing rows, which locked every title the device
// has until commit, in map-iteration (random) order: concurrent ingests of devices with common software
// deadlocked (found by cmd/librepatch-loadsim) and otherwise queued behind each other.
func titleIDs(ctx context.Context, q *dbq.Queries, org uuid.UUID, rows []itemRow) (map[[2]string]uuid.UUID, error) {
	type pair = [2]string
	seen := map[pair]itemRow{}
	for _, r := range rows {
		if _, ok := seen[pair{r.nn, r.np}]; !ok {
			seen[pair{r.nn, r.np}] = r
		}
	}
	keys := make([]pair, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b pair) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	out := make(map[pair]uuid.UUID, len(seen))
	if len(keys) == 0 {
		return out, nil
	}
	p := dbq.InsertSoftwareTitlesParams{OrgID: org}
	for _, k := range keys {
		r := seen[k]
		p.Ids = append(p.Ids, uuid.New())
		p.NormalizedNames = append(p.NormalizedNames, k[0])
		p.NormalizedPublishers = append(p.NormalizedPublishers, k[1])
		p.DisplayNames = append(p.DisplayNames, r.dn)
		p.DisplayPublishers = append(p.DisplayPublishers, r.dp)
	}
	if err := q.InsertSoftwareTitles(ctx, p); err != nil {
		return nil, err
	}
	got, err := q.GetSoftwareTitleIDs(ctx, dbq.GetSoftwareTitleIDsParams{OrgID: org, NormalizedNames: p.NormalizedNames, NormalizedPublishers: p.NormalizedPublishers})
	if err != nil {
		return nil, err
	}
	for _, g := range got {
		out[pair{g.NormalizedName, g.NormalizedPublisher}] = g.ID
	}
	return out, nil
}

func (s *Service) writeItems(ctx context.Context, q *dbq.Queries, org, device uuid.UUID, rows []itemRow, baseline bool, now time.Time) error {
	if len(rows) == 0 {
		return nil
	}
	ids, err := titleIDs(ctx, q, org, rows)
	if err != nil {
		return err
	}
	up := dbq.UpsertSoftwareInstallsParams{DeviceID: device, Now: now}
	for _, r := range rows {
		up.Sources = append(up.Sources, r.source)
		up.Scopes = append(up.Scopes, r.scope)
		up.UserSids = append(up.UserSids, r.sid)
		up.ItemKeys = append(up.ItemKeys, r.key)
		up.TitleIds = append(up.TitleIds, ids[[2]string{r.nn, r.np}])
		up.Names = append(up.Names, r.name)
		up.Versions = append(up.Versions, r.version)
		up.VersionKeys = append(up.VersionKeys, r.versionKey)
		up.Publishers = append(up.Publishers, r.publisher)
		up.InstallDates = append(up.InstallDates, r.installDate)
		up.InstallLocations = append(up.InstallLocations, r.location)
		up.UninstallStrings = append(up.UninstallStrings, r.uninstall)
		up.QuietUninstallStrings = append(up.QuietUninstallStrings, r.quiet)
		up.ProductCodes = append(up.ProductCodes, r.productCode)
		up.SystemComponents = append(up.SystemComponents, r.system)
	}
	if !baseline { // the first ever snapshot is a baseline, not a burst of "added" events
		if err := q.RecordSoftwareChanges(ctx, dbq.RecordSoftwareChangesParams{DeviceID: device, Now: now,
			Sources: up.Sources, Scopes: up.Scopes, UserSids: up.UserSids, ItemKeys: up.ItemKeys,
			TitleIds: up.TitleIds, Names: up.Names, Versions: up.Versions}); err != nil {
			return err
		}
	}
	return q.UpsertSoftwareInstalls(ctx, up)
}

// ApplyDelta applies a revisioned delta. It returns ErrRevMismatch (and
// changes nothing) if the server's revision differs from d.BaseRev.
func (s *Service) ApplyDelta(ctx context.Context, device uuid.UUID, newRev uint64, d *agentv1.SoftwareDelta, truncated bool) error {
	if d == nil || newRev != d.BaseRev+1 || len(d.Upserts)+len(d.Removes) > MaxDeltaChanges {
		return fmt.Errorf("%w: malformed delta", ErrInvalid)
	}
	rows, err := convertItems(d.Upserts)
	if err != nil {
		return err
	}
	removes := make([]keyRow, 0, len(d.Removes))
	for _, k := range d.Removes {
		kr, err := convertKey(k)
		if err != nil {
			return err
		}
		removes = append(removes, kr)
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		lock, err := q.LockDeviceInventory(ctx, device)
		if err != nil {
			return err
		}
		if lock.SoftwareRev < 0 || uint64(lock.SoftwareRev) != d.BaseRev { // #nosec G115 -- checked non-negative
			return ErrRevMismatch
		}
		now := s.now()
		if err := s.writeItems(ctx, q, lock.OrgID, device, rows, lock.SoftwareRev == 0, now); err != nil {
			return err
		}
		if len(removes) > 0 {
			rm := dbq.RemoveSoftwareByKeysParams{DeviceID: device, Now: now}
			for _, k := range removes {
				rm.Sources, rm.Scopes, rm.UserSids, rm.ItemKeys = append(rm.Sources, k.source), append(rm.Scopes, k.scope),
					append(rm.UserSids, k.sid), append(rm.ItemKeys, k.key)
			}
			if err := q.RemoveSoftwareByKeys(ctx, rm); err != nil {
				return err
			}
		}
		return finish(ctx, q, device, newRev, now, truncated)
	})
}

// ApplySnapshot replaces a device's software with a complete snapshot.
func (s *Service) ApplySnapshot(ctx context.Context, device uuid.UUID, newRev uint64, items []*agentv1.SoftwareItem, truncated bool) error {
	if len(items) > MaxItems {
		return fmt.Errorf("%w: too many items", ErrInvalid)
	}
	rows, err := convertItems(items)
	if err != nil {
		return err
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		lock, err := q.LockDeviceInventory(ctx, device)
		if err != nil {
			return err
		}
		now := s.now()
		if err := s.writeItems(ctx, q, lock.OrgID, device, rows, lock.SoftwareRev == 0, now); err != nil {
			return err
		}
		keep := dbq.RemoveSoftwareNotInParams{DeviceID: device, Now: now}
		for _, r := range rows {
			keep.Sources, keep.Scopes, keep.UserSids, keep.ItemKeys = append(keep.Sources, r.source), append(keep.Scopes, r.scope),
				append(keep.UserSids, r.sid), append(keep.ItemKeys, r.key)
		}
		if err := q.RemoveSoftwareNotIn(ctx, keep); err != nil {
			return err
		}
		return finish(ctx, q, device, newRev, now, truncated)
	})
}

func finish(ctx context.Context, q *dbq.Queries, device uuid.UUID, rev uint64, now time.Time, truncated bool) error {
	if rev > 1<<62 {
		return fmt.Errorf("%w: revision out of range", ErrInvalid)
	}
	return q.FinishSoftwareSync(ctx, dbq.FinishSoftwareSyncParams{DeviceID: device, SoftwareRev: int64(rev), // #nosec G115 -- bounded above
		SoftwareUpdatedAt: &now, InventoryTruncated: truncated})
}

// ApplyUsers replaces the device's user list (a small full snapshot).
func (s *Service) ApplyUsers(ctx context.Context, device uuid.UUID, newRev uint64, users []*agentv1.DeviceUser) error {
	if len(users) > MaxUsers || newRev > 1<<62 {
		return fmt.Errorf("%w: too many users", ErrInvalid)
	}
	p := dbq.UpsertDeviceUsersParams{DeviceID: device}
	seen := map[string]bool{}
	for _, u := range users {
		if len(u.Sid) > maxSID || !sidRe.MatchString(u.Sid) {
			return fmt.Errorf("%w: bad user SID", ErrInvalid)
		}
		if seen[u.Sid] {
			continue
		}
		seen[u.Sid] = true
		name, err1 := clean(u.Username, 256)
		dom, err2 := clean(u.Domain, 256)
		path, err3 := clean(u.ProfilePath, maxPath)
		if err := errors.Join(err1, err2, err3); err != nil {
			return err
		}
		if u.LastLogon < 0 || u.LastLogon > 4_102_444_800 { // year 2100
			u.LastLogon = 0
		}
		p.Sids, p.Usernames, p.Domains, p.ProfilePaths = append(p.Sids, u.Sid), append(p.Usernames, name), append(p.Domains, dom), append(p.ProfilePaths, path)
		p.LastLogons, p.Loaded, p.SignedIns, p.IsAdmins = append(p.LastLogons, u.LastLogon), append(p.Loaded, u.Loaded), append(p.SignedIns, u.SignedIn), append(p.IsAdmins, u.IsAdmin)
	}
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		if _, err := q.LockDeviceInventory(ctx, device); err != nil {
			return err
		}
		if err := q.ReplaceUsersDelete(ctx, dbq.ReplaceUsersDeleteParams{DeviceID: device, Sids: p.Sids}); err != nil {
			return err
		}
		if len(p.Sids) > 0 {
			if err := q.UpsertDeviceUsers(ctx, p); err != nil {
				return err
			}
		}
		return q.SetUsersRev(ctx, dbq.SetUsersRevParams{ID: device, UsersRev: int64(newRev)}) // #nosec G115 -- bounded above
	})
}

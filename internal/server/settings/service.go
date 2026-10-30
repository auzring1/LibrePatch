package settings

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// Errors the API maps to statuses.
var (
	ErrNotFound = errors.New("settings: unknown section")
	ErrConflict = errors.New("settings: changed by someone else")
	ErrFormat   = errors.New("settings: not a settings file")
)

const (
	cacheTTL      = 30 * time.Second
	sealPurpose   = "settings/secret/v1"
	maxAuditValue = 1500
)

// Actor is who changes settings (for the audit trail and the lock-out check).
type Actor struct {
	Org  uuid.UUID
	User uuid.UUID
	IP   string
	// Token is true when the request came with an API token (audited as such by the audit package's context flag).
}

// Doc is one section as stored.
type Doc struct {
	Section  string         `json:"section"`
	Revision int64          `json:"revision"`
	Values   map[string]any `json:"values"`
	// SecretsSet says, per secret path, whether a value is saved (the value itself is never returned).
	SecretsSet map[string]bool `json:"secrets_set"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// Service reads and writes settings.
type Service struct {
	Pool   *pgxpool.Pool
	Sealer *kek.Sealer
	Log    *slog.Logger
	Now    func() time.Time

	// OnChange, if set, is told after a section was saved with the keys whose value changed (before and after).
	OnChange func(ctx context.Context, org uuid.UUID, section string, changes map[string]any)

	mu    sync.Mutex
	cache map[string]cached
	// single is the id of the organization, found once: the product is single-tenant per installation.
	single uuid.UUID
}

type cached struct {
	doc Doc
	at  time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func (s *Service) invalidate(org uuid.UUID, section string) {
	s.mu.Lock()
	delete(s.cache, org.String()+"/"+section)
	s.mu.Unlock()
}

// Org returns the organization that unauthenticated code paths (the console's IP allow-list, the sign-in page's
// notice) read settings for. The product has one organization per installation.
func (s *Service) Org(ctx context.Context) (uuid.UUID, error) {
	s.mu.Lock()
	id := s.single
	s.mu.Unlock()
	if id != uuid.Nil {
		return id, nil
	}
	id, err := dbq.New(s.Pool).FirstOrganization(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	s.mu.Lock()
	s.single = id
	s.mu.Unlock()
	return id, nil
}

// Get returns a section, with defaults for anything never saved. The result is a copy; callers may keep it.
func (s *Service) Get(ctx context.Context, org uuid.UUID, section string) (Doc, error) {
	sec, ok := ByID(section)
	if !ok {
		return Doc{}, ErrNotFound
	}
	key := org.String() + "/" + section
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && s.now().Sub(c.at) < cacheTTL {
		d := c.doc
		s.mu.Unlock()
		d.Values = deepCopy(d.Values)
		d.SecretsSet = copySet(d.SecretsSet)
		return d, nil
	}
	s.mu.Unlock()
	doc, err := s.load(ctx, dbq.New(s.Pool), org, sec)
	if err != nil {
		return Doc{}, err
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]cached{}
	}
	s.cache[key] = cached{doc: doc, at: s.now()}
	s.mu.Unlock()
	doc.Values = deepCopy(doc.Values)
	doc.SecretsSet = copySet(doc.SecretsSet)
	return doc, nil
}

func copySet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *Service) load(ctx context.Context, q *dbq.Queries, org uuid.UUID, sec Section) (Doc, error) {
	row, err := q.GetSettingsSection(ctx, dbq.GetSettingsSectionParams{OrgID: org, Section: sec.ID})
	if store.IsNoRows(err) {
		return Doc{Section: sec.ID, Values: sec.Defaults(), SecretsSet: map[string]bool{}}, nil
	}
	if err != nil {
		return Doc{}, err
	}
	return s.decode(sec, row)
}

func (s *Service) decode(sec Section, row dbq.SettingsSection) (Doc, error) {
	if int(row.SchemaVersion) > SchemaVersion {
		return Doc{}, fmt.Errorf("settings: %s was written by a newer version (schema %d, this server understands %d)", sec.ID, row.SchemaVersion, SchemaVersion)
	}
	var vals map[string]any
	if err := json.Unmarshal(row.Data, &vals); err != nil {
		return Doc{}, err
	}
	vals, err := migrate(sec.ID, int(row.SchemaVersion), vals)
	if err != nil {
		return Doc{}, err
	}
	// Fill anything added since the document was saved, and drop what no longer exists, so readers always see the
	// current shape.
	norm, errs := sec.Normalize(dropUnknown(sec.Fields, vals))
	if len(errs) > 0 {
		// A stored value that no longer validates (a limit was tightened): serve it as is rather than lock the
		// installation out of its own settings; the next save will have to fix it.
		s.log().Warn("stored settings no longer validate", "section", sec.ID, "errors", errs.Error())
		norm = vals
		for k, v := range sec.Defaults() {
			if _, ok := norm[k]; !ok {
				norm[k] = v
			}
		}
	}
	var sealed map[string]string
	_ = json.Unmarshal(row.Secrets, &sealed)
	set := map[string]bool{}
	for k := range sealed {
		set[k] = true
	}
	return Doc{Section: sec.ID, Revision: row.Revision, Values: norm, SecretsSet: set, UpdatedAt: row.UpdatedAt}, nil
}

func dropUnknown(fields []Field, in map[string]any) map[string]any {
	out := map[string]any{}
	for _, f := range fields {
		v, ok := in[f.Key]
		if !ok || f.Kind == Secret {
			continue
		}
		if f.Kind == List {
			if arr, ok := v.([]any); ok {
				var built map[string]bool // a fixed list keeps only the items that are still built in
				if f.Fixed {
					built = optsSet(findOptions(f))
				}
				items := make([]any, 0, len(arr))
				for _, e := range arr {
					if m, ok := e.(map[string]any); ok {
						if built != nil {
							if key, _ := m[f.ItemKey].(string); !built[key] {
								continue
							}
						}
						items = append(items, dropUnknown(f.Fields, m))
					}
				}
				if f.Fixed {
					items = addMissingBuiltIns(f, items)
				}
				v = items
			}
		}
		if f.Kind == Multi { // a choice that is no longer offered (a retired event) is dropped
			if ss, ok := toStrings(v); ok {
				offered := optsSet(f.Options)
				kept := make([]string, 0, len(ss))
				for _, x := range ss {
					if offered[x] {
						kept = append(kept, x)
					}
				}
				if len(kept) == 0 && len(ss) > 0 {
					continue // nothing valid is left: fall back to the default
				}
				v = toAny(kept)
			}
		}
		out[f.Key] = v
	}
	return out
}

// addMissingBuiltIns gives a fixed list the built-in items that did not exist when the document was saved (a new
// notification event, say), with their default values, so an installation keeps loading and saving its settings after
// an upgrade instead of failing on "must keep all of its built-in items".
func addMissingBuiltIns(f Field, items []any) []any {
	have := map[string]bool{}
	for _, e := range items {
		if m, ok := e.(map[string]any); ok {
			key, _ := m[f.ItemKey].(string)
			have[key] = true
		}
	}
	defaults, _ := f.Default.([]any)
	for _, d := range defaults {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		if key, _ := m[f.ItemKey].(string); !have[key] {
			items = append(items, deepCopy(m))
		}
	}
	return items
}

// migrate upgrades a stored document to the current schema. There is one version so far.
func migrate(_ string, from int, vals map[string]any) (map[string]any, error) {
	if from < 1 {
		return nil, fmt.Errorf("settings: unknown schema version %d", from)
	}
	return vals, nil
}

// secretPaths lists where a section keeps secrets: top-level fields ("smtp_password") and the secret fields of list
// items ("webhooks.<item id>.secret").
type secretInput map[string]*string // nil pointer = leave as it is; "" = clear; text = set

// prepare assigns ids to list items that have none and pulls the secrets out of the request.
func prepare(sec Section, in map[string]any) (map[string]any, secretInput, map[string]bool, error) {
	clean := map[string]any{}
	secrets := secretInput{}
	clears := map[string]bool{}
	for k, v := range in {
		clean[k] = v
	}
	for _, f := range sec.Fields {
		switch f.Kind {
		case Secret:
			v, present := in[f.Key]
			delete(clean, f.Key)
			if !present || v == nil {
				continue
			}
			str, ok := v.(string)
			if !ok {
				return nil, nil, nil, FieldErrors{f.Key: "must be text"}
			}
			if f.Max > 0 && len(str) > f.Max {
				return nil, nil, nil, FieldErrors{f.Key: fmt.Sprintf("is longer than %d characters", f.Max)}
			}
			secrets[f.Key] = &str
		case List:
			arr, ok := in[f.Key].([]any)
			if !ok {
				continue
			}
			items := make([]any, 0, len(arr))
			for i, e := range arr {
				m, ok := e.(map[string]any)
				if !ok {
					items = append(items, e)
					continue
				}
				m = shallow(m)
				if _, hasID := findField(f.Fields, "id"); hasID {
					if id, _ := m["id"].(string); id == "" {
						m["id"] = uuid.NewString()
					}
				}
				id, _ := m["id"].(string)
				for _, sub := range f.Fields {
					if sub.Kind != Secret {
						continue
					}
					v, present := m[sub.Key]
					delete(m, sub.Key)
					if !present || v == nil {
						continue
					}
					str, ok := v.(string)
					if !ok {
						return nil, nil, nil, FieldErrors{fmt.Sprintf("%s[%d].%s", f.Key, i, sub.Key): "must be text"}
					}
					if str != "" {
						secrets[f.Key+"."+id+"."+sub.Key] = &str
					}
				}
				if cl, _ := m["clear_secret"].(bool); cl {
					for _, sub := range f.Fields {
						if sub.Kind == Secret {
							empty := ""
							secrets[f.Key+"."+id+"."+sub.Key] = &empty
							clears[f.Key+"."+id+"."+sub.Key] = true
						}
					}
					m["clear_secret"] = false
				}
				items = append(items, m)
			}
			clean[f.Key] = items
		}
	}
	return clean, secrets, clears, nil
}

func shallow(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// livePaths returns the secret paths that can still exist for the given values (top-level secrets and the secrets of
// items that are still in their lists), so secrets of deleted items are dropped.
func livePaths(sec Section, vals map[string]any) map[string]bool {
	live := map[string]bool{}
	for _, f := range sec.Fields {
		switch f.Kind {
		case Secret:
			live[f.Key] = true
		case List:
			arr, _ := vals[f.Key].([]any)
			for _, e := range arr {
				m, _ := e.(map[string]any)
				id, _ := m["id"].(string)
				for _, sub := range f.Fields {
					if sub.Kind == Secret && id != "" {
						live[f.Key+"."+id+"."+sub.Key] = true
					}
				}
			}
		}
	}
	return live
}

// Put validates and saves one section. rev is the revision the caller edited (0 if the section was never saved).
func (s *Service) Put(ctx context.Context, a Actor, section string, rev int64, in map[string]any) (Doc, error) {
	sec, ok := ByID(section)
	if !ok {
		return Doc{}, ErrNotFound
	}
	if in == nil {
		in = map[string]any{}
	}
	// Keys the caller left out keep their saved values (a PUT with part of a section is a patch of that section).
	var out Doc
	var changed map[string]any
	err := store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		cur, err := q.GetSettingsSectionForUpdate(ctx, dbq.GetSettingsSectionForUpdateParams{OrgID: a.Org, Section: sec.ID})
		exists := err == nil
		if err != nil && !store.IsNoRows(err) {
			return err
		}
		var curRev int64
		var before Doc
		sealed := map[string]string{}
		if exists {
			curRev = cur.Revision
			if before, err = s.decode(sec, cur); err != nil {
				return err
			}
			_ = json.Unmarshal(cur.Secrets, &sealed)
		} else {
			before = Doc{Section: sec.ID, Values: sec.Defaults(), SecretsSet: map[string]bool{}}
		}
		if rev != curRev {
			return ErrConflict
		}
		merged := deepCopy(before.Values)
		for k, v := range in {
			merged[k] = v
		}
		clean, secrets, _, err := prepare(sec, merged)
		if err != nil {
			return err
		}
		vals, errs := sec.Normalize(clean)
		if len(errs) == 0 && sec.Cross != nil {
			secretSet := map[string]bool{}
			for k := range sealed {
				secretSet[k] = true
			}
			for k, v := range secrets {
				if v != nil && *v != "" {
					secretSet[k] = true
				} else if v != nil {
					delete(secretSet, k)
				}
			}
			for k, v := range sec.Cross(vals, secretSet, a) {
				errs[k] = v
			}
		}
		if len(errs) > 0 {
			return errs
		}
		// Seal secrets.
		for p, v := range secrets {
			if v == nil {
				continue
			}
			if *v == "" {
				delete(sealed, p)
				continue
			}
			if s.Sealer == nil {
				return errors.New("settings: no sealer configured")
			}
			ct, err := s.Sealer.Seal(sealPurpose+"/"+a.Org.String()+"/"+sec.ID+"/"+p, []byte(*v))
			if err != nil {
				return err
			}
			sealed[p] = base64.StdEncoding.EncodeToString(ct)
		}
		live := livePaths(sec, vals)
		for p := range sealed {
			if !live[p] {
				delete(sealed, p)
			}
		}
		dataJSON, _ := json.Marshal(vals)
		secJSON, _ := json.Marshal(sealed)
		now := s.now()
		if exists {
			n, err := q.UpdateSettingsSection(ctx, dbq.UpdateSettingsSectionParams{OrgID: a.Org, Section: sec.ID, Revision: curRev, SchemaVersion: SchemaVersion,
				Data: dataJSON, Secrets: secJSON, UpdatedAt: now, UpdatedBy: &a.User})
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrConflict
			}
		} else if err := q.InsertSettingsSection(ctx, dbq.InsertSettingsSectionParams{OrgID: a.Org, Section: sec.ID, SchemaVersion: SchemaVersion,
			Data: dataJSON, Secrets: secJSON, UpdatedAt: now, UpdatedBy: &a.User}); err != nil {
			return err
		}
		set := map[string]bool{}
		for p := range sealed {
			set[p] = true
		}
		out = Doc{Section: sec.ID, Revision: curRev + 1, Values: vals, SecretsSet: set, UpdatedAt: now}
		changes := Diff(sec, before.Values, vals)
		changed = changes
		for p, v := range secrets {
			switch {
			case v == nil:
			case *v == "" && before.SecretsSet[p]:
				changes[p] = map[string]any{"before": "(set)", "after": "(cleared)"}
			case *v != "":
				changes[p] = map[string]any{"before": secretWord(before.SecretsSet[p]), "after": "(set)"}
			}
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &a.Org, ActorType: audit.ActorUser, ActorID: a.User.String(), ActorIP: a.IP, Action: "settings.update",
			TargetType: "settings", TargetIDs: []string{sec.ID}, Outcome: audit.Success,
			Details: map[string]any{"section": sec.ID, "revision": curRev + 1, "changes": changes}}, now)
		return err
	})
	if err != nil {
		return Doc{}, err
	}
	s.invalidate(a.Org, sec.ID)
	if s.OnChange != nil && len(changed) > 0 {
		s.OnChange(ctx, a.Org, sec.ID, changed)
	}
	return out, nil
}

func secretWord(set bool) string {
	if set {
		return "(set)"
	}
	return "(not set)"
}

// Diff returns, for every key whose value changed, its before and after (long values are shortened for the audit log).
func Diff(sec Section, before, after map[string]any) map[string]any {
	out := map[string]any{}
	for _, f := range sec.Fields {
		if f.Kind == Secret {
			continue
		}
		b, a := before[f.Key], after[f.Key]
		if reflect.DeepEqual(norm(b), norm(a)) {
			continue
		}
		out[f.Key] = map[string]any{"before": short(b), "after": short(a)}
	}
	return out
}

func norm(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func ellipsize(s string) string {
	if len(s) > maxAuditValue {
		return text.Truncate(s, maxAuditValue) + "…"
	}
	return s
}

func short(v any) any {
	switch x := v.(type) {
	case []any, map[string]any, []string:
		b, _ := json.Marshal(x)
		return ellipsize(string(b))
	case string:
		return ellipsize(x)
	}
	return v
}

// Secret returns a saved secret in the clear, for the code that needs it (sending mail, signing a webhook). Callers
// must not log it.
func (s *Service) Secret(ctx context.Context, org uuid.UUID, section, path string) (string, error) {
	row, err := dbq.New(s.Pool).GetSettingsSection(ctx, dbq.GetSettingsSectionParams{OrgID: org, Section: section})
	if store.IsNoRows(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var sealed map[string]string
	_ = json.Unmarshal(row.Secrets, &sealed)
	enc, ok := sealed[path]
	if !ok {
		return "", nil
	}
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	pt, err := s.Sealer.Open(sealPurpose+"/"+org.String()+"/"+section+"/"+path, ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ---- export and import ----

// ExportDoc is the settings file. It carries values only: no secrets, and nothing outside the registry.
type ExportDoc struct {
	Format        string                    `json:"format"`
	SchemaVersion int                       `json:"schema_version"`
	ExportedAt    time.Time                 `json:"exported_at"`
	Sections      map[string]map[string]any `json:"sections"`
}

// ExportFormat identifies a settings file.
const ExportFormat = "librepatch-settings"

// Export returns every section's values (never secrets).
func (s *Service) Export(ctx context.Context, org uuid.UUID) (ExportDoc, error) {
	out := ExportDoc{Format: ExportFormat, SchemaVersion: SchemaVersion, ExportedAt: s.now().UTC(), Sections: map[string]map[string]any{}}
	for _, sec := range Sections {
		d, err := s.Get(ctx, org, sec.ID)
		if err != nil {
			return out, err
		}
		out.Sections[sec.ID] = d.Values
	}
	return out, nil
}

// ImportReport says what an import changed (or would change) section by section.
type ImportReport struct {
	Section string         `json:"section"`
	Changed bool           `json:"changed"`
	Changes map[string]any `json:"changes,omitempty"`
	Errors  FieldErrors    `json:"errors,omitempty"`
	Skipped string         `json:"skipped,omitempty"`
}

// Import applies a settings file. With dryRun it only validates and reports. allowed says which sections the caller
// may change; others are reported as skipped. Imports are all-or-nothing per run: if any section fails validation,
// nothing is written.
func (s *Service) Import(ctx context.Context, a Actor, doc ExportDoc, dryRun bool, allowed func(perm string) bool) ([]ImportReport, error) {
	if doc.Format != ExportFormat {
		return nil, ErrFormat
	}
	if doc.SchemaVersion < 1 || doc.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: schema version %d is not supported (this server reads up to %d)", ErrFormat, doc.SchemaVersion, SchemaVersion)
	}
	ids := make([]string, 0, len(doc.Sections))
	for id := range doc.Sections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var reports []ImportReport
	type plan struct {
		sec  Section
		rev  int64
		vals map[string]any
	}
	var plans []plan
	bad := false
	for _, id := range ids {
		sec, ok := ByID(id)
		if !ok {
			reports = append(reports, ImportReport{Section: id, Skipped: "this server has no such section"})
			continue
		}
		if !allowed(sec.Perm) {
			reports = append(reports, ImportReport{Section: id, Skipped: "you may not change this section"})
			continue
		}
		cur, err := s.Get(ctx, a.Org, id)
		if err != nil {
			return nil, err
		}
		in, _, _, err := prepare(sec, doc.Sections[id])
		if err != nil {
			var fe FieldErrors
			if errors.As(err, &fe) {
				reports = append(reports, ImportReport{Section: id, Errors: fe})
				bad = true
				continue
			}
			return nil, err
		}
		vals, errs := sec.Normalize(in)
		if len(errs) == 0 && sec.Cross != nil {
			set := cur.SecretsSet
			for k, v := range sec.Cross(vals, set, a) {
				errs[k] = v
			}
		}
		if len(errs) > 0 {
			reports = append(reports, ImportReport{Section: id, Errors: errs})
			bad = true
			continue
		}
		changes := Diff(sec, cur.Values, vals)
		reports = append(reports, ImportReport{Section: id, Changed: len(changes) > 0, Changes: changes})
		if len(changes) > 0 {
			plans = append(plans, plan{sec, cur.Revision, vals})
		}
	}
	if dryRun || bad {
		return reports, nil
	}
	for _, p := range plans {
		if _, err := s.Put(ctx, a, p.sec.ID, p.rev, p.vals); err != nil {
			return reports, err
		}
	}
	return reports, nil
}

// ---- typed access for the code that enforces settings ----

// V gives typed reads of a section's values.
type V map[string]any

// Int returns an int setting.
func (v V) Int(key string) int { n, _ := toInt(v[key]); return n }

// Bool returns a bool setting.
func (v V) Bool(key string) bool { b, _ := v[key].(bool); return b }

// Str returns a string setting.
func (v V) Str(key string) string { s, _ := v[key].(string); return s }

// Strings returns a list-of-strings setting.
func (v V) Strings(key string) []string { ss, _ := toStrings(v[key]); return ss }

// Items returns the objects of a list setting.
func (v V) Items(key string) []V {
	arr, _ := v[key].([]any)
	out := make([]V, 0, len(arr))
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, V(m))
		}
	}
	return out
}

// Peek is Values without the defensive copy, for hot paths such as a per-request check. The caller must not modify
// the result.
func (s *Service) Peek(ctx context.Context, org uuid.UUID, section string) V {
	key := org.String() + "/" + section
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && s.now().Sub(c.at) < cacheTTL {
		d := c.doc
		s.mu.Unlock()
		return V(d.Values)
	}
	s.mu.Unlock()
	return s.Values(ctx, org, section)
}

// Saved reports whether the section has ever been saved (until then the server's own configuration applies where it
// has one, for example session timeouts from the environment).
func (s *Service) Saved(ctx context.Context, org uuid.UUID, section string) bool {
	d, err := s.Get(ctx, org, section)
	return err == nil && d.Revision > 0
}

// Values returns a section's typed values for org, or the defaults if reading fails (settings must never take the
// product down: callers that enforce something fall back to the built-in default).
func (s *Service) Values(ctx context.Context, org uuid.UUID, section string) V {
	d, err := s.Get(ctx, org, section)
	if err != nil {
		s.log().Error("read settings", "section", section, "err", err)
		sec, _ := ByID(section)
		return V(sec.Defaults())
	}
	return V(d.Values)
}

// InAllowlist reports whether ip is covered by the list (an empty list allows everyone).
func InAllowlist(list []string, ip string) bool {
	if len(list) == 0 {
		return true
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return false
	}
	for _, e := range list {
		if strings.Contains(e, "/") {
			if _, n, err := net.ParseCIDR(e); err == nil && n.Contains(addr) {
				return true
			}
		} else if p := net.ParseIP(e); p != nil && p.Equal(addr) {
			return true
		}
	}
	return false
}

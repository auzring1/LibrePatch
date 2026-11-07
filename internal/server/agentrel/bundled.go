package agentrel

// The agent release that came with the server image (D149). The image workflow builds and signs the agent first and puts
// the executable and its .lprel file into the image; when the server runs it registers that release for every organization
// by itself, exactly as if an administrator had uploaded the two files, and makes it the rollout target when it is newer
// than the current one, so updating the Docker stack is all it takes to update the agents (D149, always on since D164).
//
// Nothing here widens trust: the bundle is verified against the same release keys as an upload, and every agent verifies
// it again against the key compiled into it.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/store"
	"github.com/auzring1/librepatch/internal/shared/release"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// bundledActorID is how the audit log names the server itself when it registers or selects its bundled release.
const bundledActorID = "server-image"

// bundled is the release found in the image's directory.
type bundled struct {
	bundle []byte
	exe    string // path of the agent executable
	m      *release.Manifest
}

// bundledState remembers which organization already has which version, so a quiet minute costs one directory read.
type bundledState struct {
	done map[string]bool // "organization/version" pairs that were handled
	mu   sync.Mutex
}

// loadBundled reads and verifies the newest usable release in dir. The directory is read on every call (the files are
// small and the call happens once a minute), so a release that appears while the server runs is picked up too. It returns
// nil, with the reason logged once per file, when there is none (a build without an update signing key, or a server that
// does not trust the key).
func (s *Service) loadBundled() *bundled {
	if s.BundledDir == "" {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join(s.BundledDir, "*.lprel"))
	var best *bundled
	for _, path := range files {
		raw, err := os.ReadFile(path) // #nosec G304 -- a file of the server image, not user input
		if err != nil {
			s.warnOnce(path, "bundled agent release: cannot read the update file", "file", path, "err", err)
			continue
		}
		b, err := release.DecodeBundle(raw)
		if err != nil {
			s.warnOnce(path, "bundled agent release: bad update file", "file", path, "err", err)
			continue
		}
		m, err := release.Verify(s.keys(), b.Manifest, b.Signature, b.KeyID)
		if err != nil {
			s.warnOnce(path, "bundled agent release: not used, because the server does not trust its signing key. Set LIBREPATCH_RELEASE_PUBLIC_KEYS in deploy/.env to your update public key", "file", path, "err", err)
			continue
		}
		if best != nil {
			if ck, nk := vercmp.Key(best.m.Version), vercmp.Key(m.Version); nk == nil || (ck != nil && string(nk) <= string(ck)) {
				continue
			}
		}
		best = &bundled{bundle: raw, exe: filepath.Join(filepath.Dir(path), filepath.Base(path[:len(path)-len(".lprel")])+".exe"), m: m}
	}
	if best != nil {
		s.infoOnce("found:"+best.exe+best.m.Version, "agent release found in the server image", "file", best.exe, "version", best.m.Version)
	}
	return best
}

// warnOnce and infoOnce log a message the first time its key is seen, so the minute loop does not repeat it.
func (s *Service) warnOnce(key, msg string, args ...any) {
	if s.firstTime(key) {
		s.log().Warn(msg, args...)
	}
}

func (s *Service) infoOnce(key, msg string, args ...any) {
	if s.firstTime(key) {
		s.log().Info(msg, args...)
	}
}

func (s *Service) firstTime(key string) bool {
	s.bd.mu.Lock()
	defer s.bd.mu.Unlock()
	if s.bd.done == nil {
		s.bd.done = map[string]bool{}
	}
	if s.bd.done["log:"+key] {
		return false
	}
	s.bd.done["log:"+key] = true
	return true
}

// SyncBundled registers the bundled release for every organization that does not have it yet and, where an organization
// needs it, makes it the rollout target. It is cheap once every organization was handled, so the housekeeping loop
// calls it every minute (an organization created after the server started, by the first-run setup, is picked up too).
func (s *Service) SyncBundled(ctx context.Context) {
	if s.BundledDir == "" || s.Content == nil {
		return
	}
	b := s.loadBundled()
	if b == nil {
		return
	}
	orgs, err := dbq.New(s.Pool).ListOrgIDs(ctx)
	if err != nil {
		s.log().Warn("bundled agent release: listing organizations", "err", err)
		return
	}
	for _, org := range orgs {
		key := org.String() + "/" + b.m.Version
		s.bd.mu.Lock()
		done := s.bd.done[key]
		s.bd.mu.Unlock()
		if done {
			continue
		}
		if err := s.syncBundledOrg(ctx, org, b); err != nil {
			s.log().Warn("bundled agent release", "org", org, "version", b.m.Version, "err", err)
			continue
		}
		s.bd.mu.Lock()
		if s.bd.done == nil {
			s.bd.done = map[string]bool{}
		}
		s.bd.done[key] = true
		s.bd.mu.Unlock()
	}
}

func (s *Service) syncBundledOrg(ctx context.Context, org uuid.UUID, b *bundled) error {
	q := dbq.New(s.Pool)
	rels, err := q.ListAgentReleases(ctx, org)
	if err != nil {
		return err
	}
	var id uuid.UUID
	for _, r := range rels {
		if r.Version == b.m.Version && r.Os == b.m.OS && r.Arch == b.m.Arch {
			id = r.ID
		}
	}
	if id == uuid.Nil {
		f, err := os.Open(b.exe) // #nosec G304 -- a file of the server image
		if err != nil {
			return fmt.Errorf("the agent executable that belongs to the update file is missing: %w", err)
		}
		defer f.Close()
		rel, err := s.AddRelease(ctx, Actor{Org: org}, b.bundle, f)
		if err != nil {
			if errors.Is(err, ErrConflict) { // another server instance registered it meanwhile
				return nil
			}
			return err
		}
		id = rel.ID
		s.log().Info("agent release added from the server image", "org", org, "version", rel.Version)
	}
	return s.autoTarget(ctx, org, id, b.m.Version)
}

// autoTarget makes the release that came with the image the rollout target when it is newer than the current target (or
// there is none). An older image never moves the target backwards, so a restart cannot undo an administrator's choice of a
// newer release, and a paused rollout stays paused.
func (s *Service) autoTarget(ctx context.Context, org, id uuid.UUID, version string) error {
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		ro, err := q.GetAgentRollout(ctx, org)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && ro.ReleaseID != nil {
			if *ro.ReleaseID == id {
				return nil
			}
			cur, err := q.GetAgentRelease(ctx, dbq.GetAgentReleaseParams{OrgID: org, ID: *ro.ReleaseID})
			if err == nil {
				ck, nk := vercmp.Key(cur.Version), vercmp.Key(version)
				if nk == nil || (ck != nil && string(nk) <= string(ck)) {
					return nil
				}
			}
		}
		now := s.now()
		if err := q.UpsertAgentRolloutTarget(ctx, dbq.UpsertAgentRolloutTargetParams{OrgID: org, ReleaseID: &id, StartedAt: &now}); err != nil {
			return err
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: bundledActorID, Action: "agent.rollout_set",
			TargetType: "organization", TargetIDs: []string{org.String()}, Outcome: audit.Success,
			Details: map[string]any{"auto": true, "release": id.String(), "version": version}}, now)
		if err == nil {
			s.log().Info("agent rollout target set to the release from the server image", "org", org, "version", version)
		}
		return err
	})
}

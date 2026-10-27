package agentrel

// The agent release that came with the server image (D149). The image workflow builds and signs the agent first and puts
// the executable and its .lprel file into the image; when the server runs it registers that release for every organization
// by itself, exactly as if an administrator had uploaded the two files. When an organization switched on "roll out new
// versions automatically", a release that is newer than the current target becomes the target, so updating the Docker
// stack is all it takes to update the agents (through the pilot group, soak time and success threshold already set).
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

// bundledState is read once: the directory does not change while the server runs.
type bundledState struct {
	once sync.Once
	b    *bundled
	done map[uuid.UUID]bool // organizations that were handled
	// pending holds a release this process added and has not yet offered as the rollout target (a failed attempt is retried).
	pending map[uuid.UUID]uuid.UUID
	mu      sync.Mutex
}

// loadBundled reads and verifies the first usable release in dir. It returns nil, with the reason logged, when there is
// none (a build without an update signing key, or a server that does not trust the key).
func (s *Service) loadBundled() *bundled {
	s.bd.once.Do(func() {
		if s.BundledDir == "" {
			return
		}
		files, _ := filepath.Glob(filepath.Join(s.BundledDir, "*.lprel"))
		if len(files) == 0 {
			return
		}
		path := files[0]
		raw, err := os.ReadFile(path) // #nosec G304 -- a file of the server image, not user input
		if err != nil {
			s.log().Warn("bundled agent release: cannot read the update file", "file", path, "err", err)
			return
		}
		b, err := release.DecodeBundle(raw)
		if err != nil {
			s.log().Warn("bundled agent release: bad update file", "file", path, "err", err)
			return
		}
		m, err := release.Verify(s.keys(), b.Manifest, b.Signature, b.KeyID)
		if err != nil {
			s.log().Warn("bundled agent release: not used, because the server does not trust its signing key. Set LIBREPATCH_RELEASE_PUBLIC_KEYS in deploy/.env to your update public key", "file", path, "err", err)
			return
		}
		s.log().Info("agent release found in the server image", "file", path, "version", m.Version)
		s.bd.b = &bundled{bundle: raw, exe: filepath.Join(filepath.Dir(path), filepath.Base(path[:len(path)-len(".lprel")])+".exe"), m: m}
	})
	return s.bd.b
}

// SyncBundled registers the bundled release for every organization that does not have it yet and, where an organization
// asked for it, makes it the rollout target. It is cheap once every organization was handled, so the housekeeping loop
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
		s.bd.mu.Lock()
		done := s.bd.done[org]
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
			s.bd.done = map[uuid.UUID]bool{}
		}
		s.bd.done[org] = true
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
		s.bd.mu.Lock()
		if s.bd.pending == nil {
			s.bd.pending = map[uuid.UUID]uuid.UUID{}
		}
		s.bd.pending[org] = id
		s.bd.mu.Unlock()
		s.log().Info("agent release added from the server image", "org", org, "version", rel.Version)
	}
	// Only a release added just now can become the target: one an earlier start registered stays as an administrator left it.
	s.bd.mu.Lock()
	pid, ok := s.bd.pending[org]
	s.bd.mu.Unlock()
	if !ok {
		return nil
	}
	if err := s.autoTarget(ctx, org, pid, b.m.Version); err != nil {
		return err
	}
	s.bd.mu.Lock()
	delete(s.bd.pending, org)
	s.bd.mu.Unlock()
	return nil
}

// autoTarget makes a newly added release the rollout target when the organization asked for that and the release is
// newer than the current target. A paused rollout stays paused: an administrator (or a failed pilot) stopped it.
func (s *Service) autoTarget(ctx context.Context, org, id uuid.UUID, version string) error {
	return store.Tx(ctx, s.Pool, func(tx pgx.Tx, q *dbq.Queries) error {
		ro, err := q.GetAgentRollout(ctx, org)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !ro.AutoNewRelease) {
			return nil
		}
		if err != nil {
			return err
		}
		if ro.ReleaseID != nil {
			cur, err := q.GetAgentRelease(ctx, dbq.GetAgentReleaseParams{OrgID: org, ID: *ro.ReleaseID})
			if err == nil {
				ck, nk := vercmp.Key(cur.Version), vercmp.Key(version)
				if nk == nil || (ck != nil && string(nk) <= string(ck)) {
					return nil
				}
			}
		}
		now := s.now()
		if _, err := q.SetAgentRolloutTarget(ctx, dbq.SetAgentRolloutTargetParams{OrgID: org, ReleaseID: &id, StartedAt: &now}); err != nil {
			return err
		}
		_, err = audit.Write(ctx, tx, audit.Entry{OrgID: &org, ActorType: audit.ActorSystem, ActorID: bundledActorID, Action: "agent.rollout_set",
			TargetType: "organization", TargetIDs: []string{org.String()}, Outcome: audit.Success,
			Details: map[string]any{"auto": true, "release": id.String(), "version": version, "paused": ro.Paused}}, now)
		if err == nil {
			s.log().Info("agent rollout target set to the release from the server image", "org", org, "version", version, "paused", ro.Paused)
		}
		return err
	})
}

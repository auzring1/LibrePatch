// Package audit writes the append-only, hash-chained audit log
// (docs/THREAT-MODEL.md T-SRV-4). Entries are written inside the caller's
// transaction so the audit record commits atomically with the change.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
)

// Actor types.
const (
	ActorUser      = "user"
	ActorSystem    = "system"
	ActorDevice    = "device"
	ActorAnonymous = "anonymous"
)

// Outcomes.
const (
	Success = "success"
	Denied  = "denied"
	Error   = "error"
)

// Entry is one audit record.
type Entry struct {
	OrgID      *uuid.UUID
	ActorType  string
	ActorID    string
	ActorIP    string
	Action     string
	TargetType string
	TargetIDs  []string
	Outcome    string
	Details    map[string]any
}

var genesis = make([]byte, 32)

type ctxKey struct{}

// WithAPIToken marks a request context as authenticated by an API token, so that every audit
// entry written under it says so (details.via_api_token).
func WithAPIToken(ctx context.Context, tokenID string) context.Context {
	return context.WithValue(ctx, ctxKey{}, tokenID)
}

// Write appends e using tx. Concurrent writers are serialized by an advisory lock.
func Write(ctx context.Context, tx pgx.Tx, e Entry, now time.Time) (int64, error) {
	if e.Action == "" || e.ActorType == "" || e.Outcome == "" {
		return 0, errors.New("audit: action, actor type and outcome are required")
	}
	q := dbq.New(tx)
	if err := q.LockAuditChain(ctx); err != nil {
		return 0, err
	}
	prev, err := q.GetLastAuditHash(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = genesis
	} else if err != nil {
		return 0, err
	}
	if id, ok := ctx.Value(ctxKey{}).(string); ok && id != "" {
		n := len(e.Details)
		if n > math.MaxInt-1 {
			return 0, errors.New("audit: details too large")
		}
		d := make(map[string]any, n+1)
		for k, v := range e.Details {
			d[k] = v
		}
		d["via_api_token"] = id
		e.Details = d
	}
	details, err := canonicalDetails(e.Details)
	if err != nil {
		return 0, err
	}
	if e.TargetIDs == nil {
		e.TargetIDs = []string{}
	}
	ts := now.UTC().Truncate(time.Microsecond)
	h := chainHash(prev, ts, e.OrgID, e.ActorType, e.ActorID, e.ActorIP, e.Action, e.TargetType, e.TargetIDs, e.Outcome, details)
	return q.InsertAudit(ctx, dbq.InsertAuditParams{
		Ts: ts, OrgID: e.OrgID, ActorType: e.ActorType, ActorID: e.ActorID, ActorIp: e.ActorIP,
		Action: e.Action, TargetType: e.TargetType, TargetIds: e.TargetIDs, Outcome: e.Outcome,
		Details: details, PrevHash: prev, Hash: h,
	})
}

// Beginner can open transactions (pgxpool.Pool satisfies it).
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Log writes e in its own transaction.
func Log(ctx context.Context, db Beginner, e Entry) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := Write(ctx, tx, e, time.Now()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VerifyResult summarizes a chain verification.
type VerifyResult struct {
	Checked int64
	// BrokenAt is the first entry whose hash or link is wrong (0 = intact).
	BrokenAt int64
}

// Verify walks the whole chain in id order.
func Verify(ctx context.Context, q *dbq.Queries) (VerifyResult, error) {
	var res VerifyResult
	prev := genesis
	var after int64
	for {
		rows, err := q.ListAuditAscending(ctx, dbq.ListAuditAscendingParams{ID: after, Limit: 1000})
		if err != nil {
			return res, err
		}
		if len(rows) == 0 {
			return res, nil
		}
		for _, r := range rows {
			details, err := recanonicalize(r.Details)
			if err != nil {
				res.BrokenAt = r.ID
				return res, nil
			}
			want := chainHash(prev, r.Ts, r.OrgID, r.ActorType, r.ActorID, r.ActorIp, r.Action, r.TargetType, r.TargetIds, r.Outcome, details)
			if !bytes.Equal(r.PrevHash, prev) || !bytes.Equal(r.Hash, want) {
				res.BrokenAt = r.ID
				return res, nil
			}
			prev = r.Hash
			after = r.ID
			res.Checked++
		}
	}
}

func chainHash(prev []byte, ts time.Time, org *uuid.UUID, actorType, actorID, actorIP, action, targetType string,
	targets []string, outcome string, details []byte) []byte {
	orgS := ""
	if org != nil {
		orgS = org.String()
	}
	// json.Marshal of a struct gives a fixed field order: a stable canonical form.
	rec, _ := json.Marshal(struct {
		TS         string          `json:"ts"`
		Org        string          `json:"org"`
		ActorType  string          `json:"actor_type"`
		ActorID    string          `json:"actor_id"`
		ActorIP    string          `json:"actor_ip"`
		Action     string          `json:"action"`
		TargetType string          `json:"target_type"`
		Targets    []string        `json:"targets"`
		Outcome    string          `json:"outcome"`
		Details    json.RawMessage `json:"details"`
	}{ts.UTC().Format(time.RFC3339Nano), orgS, actorType, actorID, actorIP, action, targetType, targets, outcome, details})
	h := sha256.New()
	h.Write([]byte("librepatch/audit/v1\x00"))
	h.Write(prev)
	h.Write(rec)
	return h.Sum(nil)
}

// canonicalDetails produces the canonical JSON stored and hashed.
func canonicalDetails(d map[string]any) ([]byte, error) {
	if d == nil {
		d = map[string]any{}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("audit details: %w", err)
	}
	return recanonicalize(raw)
}

// recanonicalize decodes and re-encodes JSON (sorted keys, normalized
// spacing) so the value read back from jsonb hashes identically.
func recanonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

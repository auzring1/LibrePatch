package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/shared/text"
)

// Session cookie names. The __Host- prefix forces Secure, Path=/ and no Domain.
const (
	cookieSecure   = "__Host-lp_session"
	cookieInsecure = "lp_session" // dev mode over plain http only
	// PreMFALifetime bounds how long a password-verified, MFA-pending session lives.
	PreMFALifetime = 5 * time.Minute
)

// ErrNoSession means the request has no valid session.
var ErrNoSession = errors.New("no valid session")

// Session is a loaded session row.
type Session struct {
	Token          string // raw cookie value (only set on creation)
	IDHash         []byte
	UserID         uuid.UUID
	MFAVerified    bool
	CSRFToken      string
	PendingTOTPEnc []byte
	MFAFailures    int32
	AbsExpiresAt   time.Time
}

// Sessions manages server-side sessions.
type Sessions struct {
	Q    func(ctx context.Context) *dbq.Queries
	Idle time.Duration
	Abs  time.Duration
	// Timeouts, when set, overrides Idle and Abs at each use (the organization's Security settings).
	Timeouts func(ctx context.Context) (idle, abs time.Duration)
	Secure   bool
	Now      func() time.Time
}

func (m *Sessions) limits(ctx context.Context) (time.Duration, time.Duration) {
	if m.Timeouts != nil {
		if i, a := m.Timeouts(ctx); i > 0 && a > 0 {
			return i, a
		}
	}
	return m.Idle, m.Abs
}

func (m *Sessions) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// CookieName returns the cookie name in use.
func (m *Sessions) CookieName() string {
	if m.Secure {
		return cookieSecure
	}
	return cookieInsecure
}

func hashToken(tok string) []byte {
	s := sha256.Sum256([]byte(tok))
	return s[:]
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create inserts a session using q (so it can join a transaction).
func (m *Sessions) Create(ctx context.Context, q *dbq.Queries, userID uuid.UUID, mfaVerified bool, ip, ua string) (*Session, error) {
	tok, err := randToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randToken()
	if err != nil {
		return nil, err
	}
	now := m.now()
	idleD, absD := m.limits(ctx)
	idle, abs := now.Add(idleD), now.Add(absD)
	var mfaAt *time.Time
	if mfaVerified {
		mfaAt = &now
	} else {
		idle, abs = now.Add(PreMFALifetime), now.Add(PreMFALifetime)
	}
	ua = text.Truncate(ua, 512)
	s := &Session{Token: tok, IDHash: hashToken(tok), UserID: userID, MFAVerified: mfaVerified, CSRFToken: csrf, AbsExpiresAt: abs}
	err = q.CreateSession(ctx, dbq.CreateSessionParams{
		IDHash: s.IDHash, UserID: userID, CreatedAt: now, LastSeenAt: now, IdleExpiresAt: idle,
		AbsExpiresAt: abs, MfaVerifiedAt: mfaAt, Ip: ip, UserAgent: ua, CsrfToken: csrf,
	})
	return s, err
}

// Lookup loads and validates the session for a raw token, sliding the idle timeout.
func (m *Sessions) Lookup(ctx context.Context, tok string) (*Session, error) {
	if tok == "" || len(tok) > 128 {
		return nil, ErrNoSession
	}
	q := m.Q(ctx)
	row, err := q.GetSession(ctx, hashToken(tok))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	now := m.now()
	if now.After(row.IdleExpiresAt) || now.After(row.AbsExpiresAt) {
		_ = q.DeleteSession(ctx, row.IDHash)
		return nil, ErrNoSession
	}
	s := &Session{IDHash: row.IDHash, UserID: row.UserID, MFAVerified: row.MfaVerifiedAt != nil,
		CSRFToken: row.CsrfToken, PendingTOTPEnc: row.PendingTotpEnc, MFAFailures: row.MfaFailures, AbsExpiresAt: row.AbsExpiresAt}
	// Slide the idle window (at most once a minute to limit writes).
	if s.MFAVerified && now.Sub(row.LastSeenAt) > time.Minute {
		idleD, _ := m.limits(ctx)
		idle := now.Add(idleD)
		if idle.After(row.AbsExpiresAt) {
			idle = row.AbsExpiresAt
		}
		_ = q.TouchSession(ctx, dbq.TouchSessionParams{IDHash: row.IDHash, LastSeenAt: now, IdleExpiresAt: idle})
	}
	return s, nil
}

// SetCookie writes the session cookie.
func (m *Sessions) SetCookie(w http.ResponseWriter, s *Session) {
	// Secure is false only in LIBREPATCH_DEV_MODE over plain http (config rejects http otherwise).
	http.SetCookie(w, &http.Cookie{ // #nosec G124 NOSONAR -- see above
		Name: m.CookieName(), Value: s.Token, Path: "/", HttpOnly: true, Secure: m.Secure,
		SameSite: http.SameSiteStrictMode, Expires: s.AbsExpiresAt,
	})
}

// ClearCookie removes the session cookie.
func (m *Sessions) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- deletion cookie; same attributes as SetCookie
		Name: m.CookieName(), Value: "", Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// TokenFromRequest returns the raw session token from the cookie.
func (m *Sessions) TokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(m.CookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

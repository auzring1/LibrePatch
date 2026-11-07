package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/auth"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

// The event stream is long-lived, so it asks reauthenticate again and again. Revoking a token, disabling its owner or
// taking the permission away has to end the stream, not just refuse the next request.
func TestReauthenticateFollowsTokenUserAndRole(t *testing.T) {
	db := pgtest.New(t)
	ctx := t.Context()
	q := dbq.New(db.Pool)
	s := &server{Deps: Deps{Pool: db.Pool, Log: slog.New(slog.DiscardHandler),
		Sessions: &auth.Sessions{Q: func(context.Context) *dbq.Queries { return q }}}}

	org, user, binding, tokenID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, err := range []error{
		q.CreateOrganization(ctx, dbq.CreateOrganizationParams{ID: org, Name: "Contoso Health"}),
		q.CreateUser(ctx, dbq.CreateUserParams{ID: user, OrgID: org, Email: "a@example.test", DisplayName: "A", PasswordHash: "x"}),
		q.CreateRoleBinding(ctx, dbq.CreateRoleBindingParams{ID: binding, UserID: user, Role: auth.RoleAdmin, ScopeType: auth.ScopeOrg, ScopeID: org}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	secret := apiTokenPrefix + "stream-test-secret"
	sum := sha256.Sum256([]byte(secret))
	if err := q.InsertAPIToken(ctx, dbq.InsertAPITokenParams{ID: tokenID, OrgID: org, UserID: user, Name: "t", Prefix: secret[:8],
		TokenHash: sum[:], Scopes: []string{auth.PermDevicesRead}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+secret)

	p, err := s.reauthenticate(req)
	if err != nil || !p.Access.HasAnywhere(auth.PermDevicesRead) || p.Access.HasAnywhere(auth.PermAuditRead) {
		t.Fatalf("a valid token keeps its scope: %v %+v", err, p)
	}

	// The owner is demoted: the token loses what the owner lost.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, binding); err != nil {
		t.Fatal(err)
	}
	if p, err := s.reauthenticate(req); err != nil || p.Access.HasAnywhere(auth.PermDevicesRead) {
		t.Fatalf("a demoted owner must not keep devices:read through the token: %v %+v", err, p)
	}
	if err := q.CreateRoleBinding(ctx, dbq.CreateRoleBindingParams{ID: uuid.New(), UserID: user, Role: auth.RoleAdmin, ScopeType: auth.ScopeOrg, ScopeID: org}); err != nil {
		t.Fatal(err)
	}

	// The owner is disabled.
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reauthenticate(req); !errors.Is(err, errInvalidToken) {
		t.Fatalf("a disabled owner: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET status = 'active' WHERE id = $1`, user); err != nil {
		t.Fatal(err)
	}

	// The token is revoked.
	now := time.Now()
	if _, err := q.RevokeAPIToken(ctx, dbq.RevokeAPITokenParams{ID: tokenID, OrgID: org, RevokedAt: &now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reauthenticate(req); !errors.Is(err, errInvalidToken) {
		t.Fatalf("a revoked token: %v", err)
	}

	// No credentials at all.
	if _, err := s.reauthenticate(httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("anonymous: %v", err)
	}
}

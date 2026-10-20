package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type fakeIdP struct {
	srv            *httptest.Server
	key            *rsa.PrivateKey
	kid            string
	issuer         string
	claims         func(c jwt.MapClaims)
	tokenReq       url.Values
	jwksHits       atomic.Int32
	idToken        string // when set, the token endpoint returns this instead of signing
	issuerOverride string
}

func newIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := f.issuer
		if f.issuerOverride != "" {
			iss = f.issuerOverride
		}
		_ = json.NewEncoder(w).Encode(Discovery{Issuer: iss, AuthorizationEndpoint: f.issuer + "/authorize", TokenEndpoint: f.issuer + "/token", JWKSURI: f.issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		e := big.NewInt(int64(key.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": f.kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.tokenReq = r.PostForm
		if f.idToken != "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": f.idToken})
			return
		}
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.issuer = f.srv.URL + "/tenant/v2.0"
	// routes are registered at the root, so serve the tenant path through a prefix strip
	h := http.StripPrefix("/tenant/v2.0", mux)
	f.srv.Config.Handler = h
	return f
}

func (f *fakeIdP) sign(t *testing.T, mut func(c jwt.MapClaims)) string {
	c := jwt.MapClaims{"iss": f.issuer, "aud": "client-1", "sub": "user-1", "nonce": "n1", "email": "a@example.test", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if mut != nil {
		mut(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = f.kid
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fakeIdP) cfg() Config {
	return Config{Issuer: f.issuer, ClientID: "client-1", ClientSecret: "s3cret", RedirectURI: "https://lp.example.test/api/v1/auth/sso/callback"}
}

func provider() *Provider { return &Provider{HTTP: http.DefaultClient, AllowHTTP: true} }

func TestAValidIDTokenIsAcceptedAndItsClaimsRead(t *testing.T) {
	f := newIdP(t)
	p := provider()
	ctx := context.Background()
	d, err := p.Discover(ctx, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Verify(ctx, d, f.cfg(), f.sign(t, func(c jwt.MapClaims) { c["roles"] = []string{"LP.Admin", "Other"}; c["amr"] = []string{"pwd", "mfa"} }), "n1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Str("sub") != "user-1" || c.Str("email") != "a@example.test" || len(c.Strings("roles")) != 2 || c.Strings("amr")[1] != "mfa" {
		t.Fatalf("%+v", c)
	}
	// The key set is cached: a second token does not fetch it again.
	if _, err := p.Verify(ctx, d, f.cfg(), f.sign(t, nil), "n1"); err != nil || f.jwksHits.Load() != 1 {
		t.Fatalf("%v hits=%d", err, f.jwksHits.Load())
	}
}

func TestForgedOrMisaddressedTokensAreRefused(t *testing.T) {
	f := newIdP(t)
	p := provider()
	ctx := context.Background()
	d, _ := p.Discover(ctx, f.issuer)
	cfg := f.cfg()
	bad := map[string]string{
		"wrong nonce":                 f.sign(t, func(c jwt.MapClaims) { c["nonce"] = "other" }),
		"no nonce":                    f.sign(t, func(c jwt.MapClaims) { delete(c, "nonce") }),
		"wrong audience":              f.sign(t, func(c jwt.MapClaims) { c["aud"] = "someone-else" }),
		"wrong issuer":                f.sign(t, func(c jwt.MapClaims) { c["iss"] = "https://evil.example/tenant/v2.0" }),
		"expired":                     f.sign(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no expiry":                   f.sign(t, func(c jwt.MapClaims) { delete(c, "exp") }),
		"from the future":             f.sign(t, func(c jwt.MapClaims) { c["iat"] = time.Now().Add(time.Hour).Unix() }),
		"no subject":                  f.sign(t, func(c jwt.MapClaims) { delete(c, "sub") }),
		"several audiences, not ours": f.sign(t, func(c jwt.MapClaims) { c["aud"] = []string{"client-1", "other"}; c["azp"] = "other" }),
	}
	for name, tok := range bad {
		if _, err := p.Verify(ctx, d, cfg, tok, "n1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Signed with a key the provider does not publish.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": f.issuer, "aud": "client-1", "sub": "admin", "nonce": "n1", "exp": time.Now().Add(time.Hour).Unix()})
	forged.Header["kid"] = f.kid
	s, _ := forged.SignedString(other)
	if _, err := p.Verify(ctx, d, cfg, s, "n1"); err == nil {
		t.Error("a token signed by another key was accepted")
	}
	// An unsigned token and a token "signed" with the public key as a shared secret.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": f.issuer, "aud": "client-1", "sub": "admin", "nonce": "n1", "exp": time.Now().Add(time.Hour).Unix()})
	s, _ = none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := p.Verify(ctx, d, cfg, s, "n1"); err == nil {
		t.Error("an unsigned token was accepted")
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": f.issuer, "aud": "client-1", "sub": "admin", "nonce": "n1", "exp": time.Now().Add(time.Hour).Unix()})
	hs.Header["kid"] = f.kid
	s, _ = hs.SignedString(f.key.N.Bytes())
	if _, err := p.Verify(ctx, d, cfg, s, "n1"); err == nil {
		t.Error("an HMAC token was accepted")
	}
	if _, err := p.Verify(ctx, d, cfg, "not a token", "n1"); err == nil {
		t.Error("garbage was accepted")
	}
}

func TestADifferentKeyIdIsFetchedOnceAndNotRepeatedly(t *testing.T) {
	f := newIdP(t)
	now := time.Now()
	p := provider()
	p.Now = func() time.Time { return now }
	ctx := context.Background()
	d, _ := p.Discover(ctx, f.issuer)
	if _, err := p.Verify(ctx, d, f.cfg(), f.sign(t, nil), "n1"); err != nil {
		t.Fatal(err)
	}
	f.kid = "rotated" // the provider rotated its key; the token names a kid we have not seen
	now = now.Add(2 * time.Minute)
	if _, err := p.Verify(ctx, d, f.cfg(), f.sign(t, nil), "n1"); err != nil {
		t.Fatalf("a rotated key must be picked up: %v", err)
	}
	hits := f.jwksHits.Load()
	now = now.Add(2 * time.Minute)
	for i := 0; i < 5; i++ {
		forged := f.sign(t, nil)
		f.kid = "unknown-" + string(rune('a'+i))
		_, _ = p.Verify(ctx, d, f.cfg(), forged, "n1")
	}
	if f.jwksHits.Load() > hits+1 {
		t.Fatalf("a stream of unknown keys made the server fetch %d times", f.jwksHits.Load()-hits)
	}
}

func TestDiscoveryMustNameTheConfiguredIssuerAndBeHTTPS(t *testing.T) {
	f := newIdP(t)
	f.issuerOverride = "https://login.evil.example/tenant/v2.0"
	if _, err := provider().Discover(context.Background(), f.issuer); err == nil {
		t.Fatal("a discovery document for another issuer was accepted")
	}
	f.issuerOverride = ""
	if _, err := (&Provider{HTTP: http.DefaultClient}).Discover(context.Background(), f.issuer); err == nil {
		t.Fatal("an http address was accepted without AllowHTTP")
	}
}

func TestAuthURLAndCodeExchange(t *testing.T) {
	f := newIdP(t)
	p := provider()
	ctx := context.Background()
	d, _ := p.Discover(ctx, f.issuer)
	verifier, challenge, err := NewPKCE()
	if err != nil || len(verifier) < 43 || verifier == challenge {
		t.Fatalf("%v %q %q", err, verifier, challenge)
	}
	u, _ := url.Parse(AuthURL(d, f.cfg(), "state-1", "nonce-1", challenge))
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "client-1" || q.Get("state") != "state-1" || q.Get("nonce") != "nonce-1" ||
		q.Get("code_challenge") != challenge || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != f.cfg().RedirectURI || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("%v", q)
	}
	f.idToken = f.sign(t, nil)
	got, err := p.Exchange(ctx, d, f.cfg(), "the-code", verifier)
	if err != nil || got != f.idToken {
		t.Fatalf("%v", err)
	}
	if f.tokenReq.Get("code") != "the-code" || f.tokenReq.Get("code_verifier") != verifier || f.tokenReq.Get("client_secret") != "s3cret" || f.tokenReq.Get("grant_type") != "authorization_code" {
		t.Fatalf("%v", f.tokenReq)
	}
	f.idToken = ""
	if _, err := p.Exchange(ctx, d, f.cfg(), "bad", verifier); err == nil {
		t.Fatal("a refused code was accepted")
	}
	a, _ := RandomToken()
	b, _ := RandomToken()
	if a == b || len(a) < 40 {
		t.Fatal("tokens must be random")
	}
}

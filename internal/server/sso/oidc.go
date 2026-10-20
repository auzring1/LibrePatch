// Package sso is the OpenID Connect side of single sign-on (D128): discovery, the authorization-code flow with PKCE, and
// the verification of the ID token. It knows nothing about users or roles.
//
// Only what the sign-in needs is done, and strictly: the provider's endpoints must be https and its discovery document must
// name the configured issuer; the ID token must be signed with RS256, PS256 or ES256 by a key from the provider's JWKS (never
// "none" or a shared-secret algorithm), carry the configured issuer and this application as audience, be neither expired nor
// issued in the future, and repeat the nonce of this sign-in. The access token is never used.
package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/auzring1/librepatch/internal/server/safehttp"
)

// Limits.
const (
	maxBody       = 1 << 20
	cacheFor      = time.Hour
	jwksRefetch   = time.Minute
	clockLeeway   = 90 * time.Second
	FlowLifetime  = 10 * time.Minute
	maxClaimItems = 500
)

// Config is the organization's registration with the provider.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Discovery is the part of the provider's metadata that is used.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Provider fetches and caches discovery documents and signing keys.
type Provider struct {
	// HTTP fetches from the provider; the default refuses loopback and link-local addresses.
	HTTP *http.Client
	// AllowHTTP accepts http endpoints. Tests only.
	AllowHTTP bool
	Now       func() time.Time

	mu        sync.Mutex
	disc      map[string]cachedDisc
	keys      map[string]cachedKeys
	lastFetch map[string]time.Time
}

type cachedDisc struct {
	d  *Discovery
	at time.Time
}

type cachedKeys struct {
	byKid map[string]any
	at    time.Time
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return safehttp.NewClient()
}

func (p *Provider) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(p.AllowHTTP && u.Scheme == "http")) {
		return fmt.Errorf("sso: %q is not an https address", raw)
	}
	return nil
}

func (p *Provider) getJSON(ctx context.Context, raw string, v any) error {
	if err := p.checkURL(raw); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client().Do(req) // #nosec G107 G704 -- an https address an administrator configured, through the client that refuses local addresses
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sso: %s answered HTTP %d", raw, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}

func trimSlash(s string) string { return strings.TrimRight(s, "/") }

// Discover returns the provider's endpoints. The document must name the configured issuer exactly.
func (p *Provider) Discover(ctx context.Context, issuer string) (*Discovery, error) {
	p.mu.Lock()
	if c, ok := p.disc[issuer]; ok && p.now().Sub(c.at) < cacheFor {
		p.mu.Unlock()
		return c.d, nil
	}
	p.mu.Unlock()
	var d Discovery
	if err := p.getJSON(ctx, trimSlash(issuer)+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	if trimSlash(d.Issuer) != trimSlash(issuer) {
		return nil, fmt.Errorf("sso: the provider says its issuer is %q, not %q", d.Issuer, issuer)
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if err := p.checkURL(e); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	if p.disc == nil {
		p.disc = map[string]cachedDisc{}
	}
	p.disc[issuer] = cachedDisc{&d, p.now()}
	p.mu.Unlock()
	return &d, nil
}

// Forget drops what is cached for an issuer (the settings changed).
func (p *Provider) Forget() {
	p.mu.Lock()
	p.disc, p.keys, p.lastFetch = nil, nil, nil
	p.mu.Unlock()
}

// RandomToken returns 32 random bytes, URL-safe.
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewPKCE returns a code verifier and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	if verifier, err = RandomToken(); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// HashState is how a state value is stored.
func HashState(state string) []byte { h := sha256.Sum256([]byte(state)); return h[:] }

// AuthURL is where to send the browser.
func AuthURL(d *Discovery, c Config, state, nonce, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("response_mode", "query")
	return d.AuthorizationEndpoint + "?" + q.Encode()
}

// Exchange trades the authorization code for the ID token.
func (p *Provider) Exchange(ctx context.Context, d *Discovery, c Config, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client().Do(req) // #nosec G107 G704 -- the provider's token endpoint from its discovery document, checked above
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return "", fmt.Errorf("sso: token endpoint: %w", err)
	}
	if resp.StatusCode != http.StatusOK || out.IDToken == "" {
		return "", fmt.Errorf("sso: token endpoint refused the code (HTTP %d %s)", resp.StatusCode, truncate(out.Error, 60))
	}
	return out.IDToken, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Claims are the claims of a verified ID token.
type Claims map[string]any

// Str returns a string claim.
func (c Claims) Str(k string) string { s, _ := c[k].(string); return s }

// Strings returns a claim that is a string or a list of strings.
func (c Claims) Strings(k string) []string {
	switch v := c[k].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
			if len(out) >= maxClaimItems {
				break
			}
		}
		return out
	}
	return nil
}

// Verify checks an ID token and returns its claims.
func (p *Provider) Verify(ctx context.Context, d *Discovery, c Config, raw, nonce string) (Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "PS256", "ES256"}), jwt.WithIssuer(c.Issuer), jwt.WithAudience(c.ClientID),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(clockLeeway), jwt.WithTimeFunc(p.now))
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return p.key(ctx, d, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("sso: the ID token is not valid: %w", err)
	}
	if got, _ := claims["nonce"].(string); nonce == "" || got != nonce {
		return nil, errors.New("sso: the ID token does not belong to this sign-in (nonce)")
	}
	// With several audiences the token must say it was issued to us.
	if aud, ok := claims["aud"].([]any); ok && len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != c.ClientID {
			return nil, errors.New("sso: the ID token has several audiences and was not issued to this application")
		}
	}
	if sub, _ := claims["sub"].(string); sub == "" || len(sub) > 255 {
		return nil, errors.New("sso: the ID token has no subject")
	}
	return Claims(claims), nil
}

func (p *Provider) key(ctx context.Context, d *Discovery, kid string) (any, error) {
	p.mu.Lock()
	c, ok := p.keys[d.JWKSURI]
	fresh := ok && p.now().Sub(c.at) < cacheFor
	last := p.lastFetch[d.JWKSURI]
	p.mu.Unlock()
	if fresh {
		if k, ok := pick(c.byKid, kid); ok {
			return k, nil
		}
	}
	// Unknown key or stale cache: fetch again, but at most once a minute, so a stream of forged tokens cannot make the server hammer the provider.
	if !last.IsZero() && p.now().Sub(last) < jwksRefetch && fresh {
		return nil, errors.New("sso: the token is signed with a key the provider does not publish")
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	p.mu.Lock()
	if p.lastFetch == nil {
		p.lastFetch = map[string]time.Time{}
	}
	p.lastFetch[d.JWKSURI] = p.now()
	p.mu.Unlock()
	if err := p.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return nil, err
	}
	byKid := map[string]any{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pub, err := k.public(); err == nil {
			byKid[k.Kid] = pub
		}
	}
	p.mu.Lock()
	if p.keys == nil {
		p.keys = map[string]cachedKeys{}
	}
	p.keys[d.JWKSURI] = cachedKeys{byKid, p.now()}
	p.mu.Unlock()
	if k, ok := pick(byKid, kid); ok {
		return k, nil
	}
	return nil, errors.New("sso: the token is signed with a key the provider does not publish")
}

// pick finds the key named kid, or the only key when the token names none and there is exactly one.
func pick(m map[string]any, kid string) (any, bool) {
	if kid != "" {
		k, ok := m[kid]
		return k, ok
	}
	if len(m) == 1 {
		for _, k := range m {
			return k, true
		}
	}
	return nil, false
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (k jwk) public() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("point not on the curve")
		}
		return pub, nil
	}
	return nil, errors.New("unsupported key type")
}

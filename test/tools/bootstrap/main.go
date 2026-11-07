// Command bootstrap drives first-run setup and creates an enrollment token
// against a freshly started server. Used by CI (Windows service install test)
// and handy for demos. It prints the enrollment string on stdout.
//
//	go run ./test/tools/bootstrap -url http://localhost:18080 -setup-token XYZ
package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	"github.com/auzring1/librepatch/internal/server/auth"
)

var totpOut, apiTokenOut *string
var maxUses *int

func main() {
	base := flag.String("url", "http://localhost:18080", "server base URL (must equal LIBREPATCH_PUBLIC_URL)")
	setupTok := flag.String("setup-token", "", "one-time setup token from the server log")
	email := flag.String("email", "admin@example.com", "admin email")
	password := flag.String("password", "Granite-Lantern-Pickle-42", "admin password")
	approval := flag.Bool("require-approval", false, "token requires approval")
	totpOut = flag.String("totp-out", "", "write the administrator's TOTP secret to this file (for later scripted logins)")
	apiTokenOut = flag.String("api-token-out", "", "also create an API token (enrollment, devices, updates, reports scopes) and write it to this file (mode 0600)")
	maxUses = flag.Int("max-uses", 5, "uses of the enrollment token")
	flag.Parse()
	if err := run(*base, *setupTok, *email, *password, *approval); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
}

func run(base, setupTok, email, password string, approval bool) error {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	csrf := ""
	do := func(method, path string, body any, out any) error {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, base+"/api/v1"+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			var e map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&e)
			return fmt.Errorf("%s: HTTP %d %v", path, resp.StatusCode, e)
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	call := func(path string, body any, out any) error { return do("POST", path, body, out) }
	var begin struct {
		TOTPSecret string `json:"totp_secret"`
	}
	if err := call("/setup/begin", map[string]any{"setup_token": setupTok, "email": email}, &begin); err != nil {
		return err
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(begin.TOTPSecret)
	if err != nil {
		return err
	}
	step := auth.TOTPStep(time.Now())
	if err := call("/setup/complete", map[string]any{"setup_token": setupTok, "org_name": "CI", "display_name": "CI Admin",
		"email": email, "password": password, "root_passphrase": "ci-root-passphrase-0123456789", "totp_code": auth.TOTPCode(secret, step)}, nil); err != nil {
		return err
	}
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := call("/auth/login", map[string]any{"email": email, "password": password}, &login); err != nil {
		return err
	}
	csrf = login.CSRF
	var mfa struct {
		CSRF string `json:"csrf_token"`
	}
	if err := call("/auth/mfa", map[string]any{"code": auth.TOTPCode(secret, step+1)}, &mfa); err != nil {
		return err
	}
	csrf = mfa.CSRF
	var tok struct {
		Enrollment string `json:"enrollment_string"`
	}
	if err := call("/enrollment-tokens", map[string]any{"name": "ci", "max_uses": *maxUses, "expires_in_hours": 2, "require_approval": approval}, &tok); err != nil {
		return err
	}
	if *apiTokenOut != "" {
		var at struct {
			Token string `json:"token"`
		}
		if err := call("/me/api-tokens", map[string]any{"name": "bootstrap", "expires_in_days": 7,
			"scopes": []string{"enrollment:write", "devices:read", "devices:write", "updates:write", "reports:read"}}, &at); err != nil {
			return err
		}
		if err := os.WriteFile(*apiTokenOut, []byte(at.Token), 0o600); err != nil {
			return err
		}
	}
	if *totpOut != "" {
		if err := os.WriteFile(*totpOut, []byte(begin.TOTPSecret), 0o600); err != nil {
			return err
		}
	}
	fmt.Println(tok.Enrollment)
	fmt.Fprintf(os.Stderr, "TOTP secret (for interactive login): %s\n", begin.TOTPSecret)
	return nil
}

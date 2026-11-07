package loadsim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// API is a minimal REST client for the parts of the server API the load test needs. It authenticates
// with an API token (Authorization: Bearer), exactly as an operator's script would.
type API struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// NewAPI builds a client. The transport keeps a few connections alive so that thousands of job
// requests do not each pay a TLS handshake.
func NewAPI(base, token string) *API {
	return &API{Base: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{MaxIdleConnsPerHost: 16, IdleConnTimeout: 60 * time.Second},
	}}
}

// APIError is a non-2xx answer.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

// do sends a request and decodes a JSON answer into out (when not nil).
func (a *API) do(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+"/api/v1"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req) // #nosec G704 -- the operator-supplied server under test
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return &APIError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// MintEnrollmentToken creates a no-approval enrollment token good for uses devices and returns the
// LP1 enrollment string.
func (a *API) MintEnrollmentToken(ctx context.Context, name string, uses int, ttl time.Duration) (string, error) {
	var out struct {
		Enrollment string `json:"enrollment_string"`
	}
	hours := max(1, int(ttl.Hours()+0.5))
	err := a.do(ctx, http.MethodPost, "/enrollment-tokens", map[string]any{
		"name": name, "max_uses": uses, "expires_in_hours": hours, "require_approval": false}, &out)
	if err != nil {
		return "", fmt.Errorf("create enrollment token: %w", err)
	}
	if out.Enrollment == "" {
		return "", errors.New("the server returned no enrollment string")
	}
	return out.Enrollment, nil
}

// CreateJob asks the server to queue a no-op job for one online device and returns the job ID.
func (a *API) CreateJob(ctx context.Context, kind, deviceID string) (string, error) {
	path := "/devices/" + deviceID + "/refresh"
	if kind == JobWUScan {
		path = "/devices/" + deviceID + "/windows-updates/scan"
	}
	var out struct {
		JobID string `json:"job_id"`
	}
	if err := a.do(ctx, http.MethodPost, path, map[string]any{}, &out); err != nil {
		return "", err
	}
	return out.JobID, nil
}

// Overview is the part of /reports/overview the tool reads: the server's own count of devices.
type Overview struct {
	Active int64
	Online int64
}

// Overview fetches the fleet counters.
func (a *API) Overview(ctx context.Context) (Overview, error) {
	var out struct {
		Devices struct {
			Active int64 `json:"active"`
			Online int64 `json:"online"`
		} `json:"devices"`
	}
	if err := a.do(ctx, http.MethodGet, "/reports/overview", nil, &out); err != nil {
		return Overview{}, err
	}
	return Overview{Active: out.Devices.Active, Online: out.Devices.Online}, nil
}

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
)

// Poster delivers one webhook call (replaced in tests).
type Poster interface {
	Post(ctx context.Context, url string, headers map[string]string, body []byte) (status int, err error)
}

type httpPoster struct{}

func (s *Service) poster() Poster {
	if s.Poster != nil {
		return s.Poster
	}
	return httpPoster{}
}

// A webhook may point at an internal receiver (that is the point of an on-premises product), but not at an address that
// reaches the server itself or its host: link-local (cloud metadata services have no legitimate receiver there),
// loopback and the unspecified address (inside the container these are the server's own listeners). The check runs on the
// address actually dialled, after name resolution, so a host name cannot be used to get around it.
func refuseLocalTargets(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsLoopback() || ip.IsUnspecified()) {
		return errors.New("webhooks cannot target link-local, loopback or unspecified addresses")
	}
	return nil
}

func (httpPoster) Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, error) {
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, Control: refuseLocalTargets}).DialContext, DisableKeepAlives: true, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// Sign returns the signature header value for a delivery: HMAC-SHA256 over "<timestamp>.<body>".
func Sign(secret string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	_, _ = m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (s *Service) deliverWebhook(ctx context.Context, org uuid.UUID, id, event string, body []byte) error {
	is := s.Settings.Values(ctx, org, "integrations")
	var url string
	found := false
	for _, w := range is.Items("webhooks") {
		if w.Str("id") == id {
			url, found = w.Str("url"), true
		}
	}
	if !found {
		return errors.New("the webhook no longer exists")
	}
	secret, err := s.Settings.Secret(ctx, org, "integrations", "webhooks."+id+".secret")
	if err != nil {
		return err
	}
	_, product := s.names(ctx)
	ts := s.now().Unix()
	h := map[string]string{"Content-Type": "application/json", "User-Agent": product, hdr("Event"): event, hdr("Delivery"): uuid.NewString(), hdr("Timestamp"): strconv.FormatInt(ts, 10)}
	if secret != "" {
		h[hdr("Signature")] = Sign(secret, ts, body)
	}
	st, err := s.poster().Post(ctx, url, h, body)
	if err != nil {
		return err
	}
	if st < 200 || st > 299 {
		return fmt.Errorf("the receiver answered HTTP %d", st)
	}
	return nil
}

func (s *Service) sendWebhookRow(ctx context.Context, r dbq.NotificationOutbox) error {
	return s.deliverWebhook(ctx, r.OrgID, r.Target, r.Event, r.Payload)
}

// TestWebhook sends a "test" event to one saved webhook right now.
func (s *Service) TestWebhook(ctx context.Context, org uuid.UUID, id string) error {
	orgName, _ := s.names(ctx)
	body, _ := json.Marshal(map[string]any{"id": uuid.NewString(), "event": "test", "time": s.now().UTC().Format(time.RFC3339), "organization": orgName, "message": "This is a test delivery."})
	return s.deliverWebhook(ctx, org, id, "test", body)
}

// hdr names a webhook header after the product (X-<Product>-<Name>), from the single source of the product name.
func hdr(name string) string { return "X-" + brand.Name + "-" + name }

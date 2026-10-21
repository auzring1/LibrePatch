package peercache

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/pki"
)

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func TestPutOpenAndTheHashMustMatch(t *testing.T) {
	c := &Cache{Dir: filepath.Join(t.TempDir(), "cache")}
	src := t.TempDir()
	data := []byte("installer bytes")
	if err := c.Put(writeFile(t, src, "a.exe", data), sum(data)); err != nil {
		t.Fatal(err)
	}
	f, err := c.Open(sum(data))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	_ = f.Close()
	if string(got) != string(data) || !c.Has(sum(data)) {
		t.Fatalf("%q", got)
	}
	// A file that does not hash to the name is never kept, so a cache cannot be filled with something else.
	if err := c.Put(writeFile(t, src, "b.exe", []byte("other")), sum(data)); err == nil {
		t.Fatal("a mismatching file was accepted")
	}
	other := sum([]byte("never put"))
	if c.Has(other) {
		t.Fatal("has a file nobody put")
	}
	if _, err := c.Open([]byte("short")); err == nil {
		t.Fatal("a short hash was accepted")
	}
	for _, bad := range []string{"", "../../etc/passwd", hex.EncodeToString(sum(data))[:63], "ZZ" + hex.EncodeToString(sum(data))[2:], hex.EncodeToString(sum(data)) + "0"} {
		if _, err := ParseName(bad); err == nil {
			t.Errorf("%q parsed as a name", bad)
		}
	}
	if _, err := ParseName(hex.EncodeToString(sum(data))); err != nil {
		t.Fatal(err)
	}
}

func TestEvictionKeepsTheNewestWithinTheLimitAndDropsOldFiles(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	c := &Cache{Dir: t.TempDir(), MaxBytes: 250, MaxAge: 24 * time.Hour, Now: func() time.Time { return now }}
	src := t.TempDir()
	var shas [][]byte
	for i := 0; i < 3; i++ {
		data := make([]byte, 100)
		data[0] = byte(i + 1)
		shas = append(shas, sum(data))
		now = now.Add(time.Minute)
		if err := c.Put(writeFile(t, src, "f", data), sum(data)); err != nil {
			t.Fatal(err)
		}
	}
	if c.Has(shas[0]) || !c.Has(shas[1]) || !c.Has(shas[2]) {
		t.Fatalf("the oldest must go first: %v %v %v", c.Has(shas[0]), c.Has(shas[1]), c.Has(shas[2]))
	}
	now = now.Add(48 * time.Hour)
	c.Evict()
	if c.Has(shas[1]) || c.Has(shas[2]) {
		t.Fatal("files unused for longer than the age limit must go")
	}
	big := make([]byte, 300)
	if err := c.Put(writeFile(t, src, "big", big), sum(big)); err == nil {
		t.Fatal("a file larger than the whole cache was kept")
	}
}

// device makes a device certificate like the server issues them.
func device(t *testing.T, a *pki.Authority) (cert, issuing []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.String()}}, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.IssueDeviceCert(csr, id, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c.Raw, a.Issuing.Cert.Raw, key
}

func authority(t *testing.T) *pki.Authority {
	h, err := pki.NewHierarchy("Contoso Health", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
}

func startServer(t *testing.T, a *pki.Authority, c *Cache, allow func(net.IP) bool) string {
	cert, iss, key := device(t, a)
	s := &Server{Cache: c, TLS: ServerTLS(a.Root, cert, iss, key), Allow: allow}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.ServeListener(ctx, ln) }()
	return "https://" + ln.Addr().String()
}

func TestAPeerServesAFileToADeviceOfTheSameInstallation(t *testing.T) {
	a := authority(t)
	c := &Cache{Dir: t.TempDir()}
	data := []byte("the installer")
	if err := c.Put(writeFile(t, t.TempDir(), "x", data), sum(data)); err != nil {
		t.Fatal(err)
	}
	base := startServer(t, a, c, func(ip net.IP) bool { return ip.IsLoopback() })
	cert, iss, key := device(t, a)
	cfg := ClientTLS(a.Root, cert, iss, key)

	resp, err := rawGet(cfg, base+"/v1/content/"+hex.EncodeToString(sum(data)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != string(data) {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if r, _ := rawGet(cfg, base+"/v1/content/"+hex.EncodeToString(sum([]byte("nope")))); r == nil || r.StatusCode != 404 {
		t.Fatalf("a file that is not cached is a 404: %+v", r)
	}
	for _, p := range []string{"/", "/v1/content/", "/v1/content/../x", "/v1/content/" + hex.EncodeToString(sum(data)) + "?x=1", "/v1/other"} {
		if r, err := rawGet(cfg, base+p); err == nil && r.StatusCode == 200 {
			t.Errorf("%s was served", p)
		}
	}
}

func TestADeviceOfAnotherInstallationOrNoCertificateIsRefused(t *testing.T) {
	a, other := authority(t), authority(t)
	c := &Cache{Dir: t.TempDir()}
	data := []byte("the installer")
	_ = c.Put(writeFile(t, t.TempDir(), "x", data), sum(data))
	base := startServer(t, a, c, func(net.IP) bool { return true })
	url := base + "/v1/content/" + hex.EncodeToString(sum(data))

	cert, iss, key := device(t, other)
	if r, err := rawGet(ClientTLS(a.Root, cert, iss, key), url); err == nil {
		t.Fatalf("a device certificate of another installation was accepted: %d", r.StatusCode)
	}
	// No client certificate at all.
	if r, err := rawGet(ClientTLS(a.Root, nil, nil, key), url); err == nil {
		t.Fatalf("no certificate was accepted: %d", r.StatusCode)
	}
	// A server of another installation is not trusted by the client either.
	base2 := startServer(t, other, c, func(net.IP) bool { return true })
	cert, iss, key = device(t, a)
	if r, err := rawGet(ClientTLS(a.Root, cert, iss, key), base2+"/v1/content/"+hex.EncodeToString(sum(data))); err == nil {
		t.Fatalf("a peer of another installation was trusted: %d", r.StatusCode)
	}
}

func TestOnlyTheLocalNetworkIsServed(t *testing.T) {
	a := authority(t)
	c := &Cache{Dir: t.TempDir()}
	data := []byte("x")
	_ = c.Put(writeFile(t, t.TempDir(), "x", data), sum(data))
	base := startServer(t, a, c, func(net.IP) bool { return false })
	cert, iss, key := device(t, a)
	r, err := rawGet(ClientTLS(a.Root, cert, iss, key), base+"/v1/content/"+hex.EncodeToString(sum(data)))
	if err != nil || r.StatusCode != http.StatusForbidden {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestValidURL(t *testing.T) {
	for _, ok := range []string{"https://192.168.1.20:7421", "https://10.0.0.5:20000", "https://172.16.4.4:1024"} {
		if _, err := ValidURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://192.168.1.20:7421", "https://example.com:7421", "https://8.8.8.8:7421", "https://127.0.0.1:7421", "https://169.254.1.1:7421",
		"https://192.168.1.20", "https://192.168.1.20:80", "https://192.168.1.20:7421/x", "https://192.168.1.20:7421?a=b", "https://user@192.168.1.20:7421",
		"https://[fd00::1]:7421", "https://192.168.1.20:70000", "ftp://192.168.1.20:7421"} {
		if _, err := ValidURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// rawGet makes the request Fetch makes, without the private-address rule (the test servers listen on loopback).
func rawGet(cfg *tls.Config, url string) (*http.Response, error) {
	tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}

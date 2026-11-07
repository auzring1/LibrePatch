package agentdl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const ver = "1.2.3"

// release is a stand-in for the GitHub release downloads.
type release struct {
	mu    sync.Mutex
	files map[string][]byte // path under /server-1.2.3/
	hits  map[string]int
}

func newRelease() *release {
	r := &release{files: map[string][]byte{}, hits: map[string]int{}}
	r.add(FileName(EXE, ver), []byte("MZ exe bytes"), true)
	r.add(FileName(MSI, ver), bytes.Repeat([]byte("msi"), 1000), true)
	return r
}

func (r *release) add(name string, body []byte, withSum bool) {
	r.files[name] = body
	if withSum {
		sum := sha256.Sum256(body)
		r.files[name+".sha256"] = []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
}

func (r *release) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := strings.TrimPrefix(req.URL.Path, "/server-"+ver+"/")
	r.hits[name]++
	b, ok := r.files[name]
	if !ok {
		http.NotFound(w, req)
		return
	}
	_, _ = w.Write(b)
}

func newService(t *testing.T, r *release) *Service {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &Service{Dir: t.TempDir(), Version: ver, BaseURL: srv.URL, AllowHTTP: true}
}

func TestFetchesBothAndVerifiesTheHash(t *testing.T) {
	s := newService(t, newRelease())
	if s.Ready() {
		t.Fatal("ready before anything was fetched")
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.Ready() {
		t.Fatal("not ready after a successful refresh")
	}
	for _, k := range Kinds {
		it, ok := s.Get(k)
		if !ok || !it.Verified || it.Size == 0 || it.FileName != FileName(k, ver) {
			t.Fatalf("%s: %+v ok=%v", k, it, ok)
		}
		f, err := it.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(f)
		_ = f.Close()
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != it.SHA256 {
			t.Fatalf("%s: stored hash does not match the stored file", k)
		}
	}
	st := s.Status()
	if !st.Enabled || len(st.Items) != 2 || st.Items[0].Kind != MSI || st.Error != "" || st.CheckedAt == nil {
		t.Fatalf("status: %+v", st)
	}
}

func TestAnInstallerWithoutAPublishedHashIsKeptButNotMarkedVerified(t *testing.T) {
	r := newRelease()
	delete(r.files, FileName(MSI, ver)+".sha256")
	s := newService(t, r)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if it, _ := s.Get(MSI); it.Verified || it.SHA256 == "" {
		t.Fatalf("msi: %+v", it)
	}
	if it, _ := s.Get(EXE); !it.Verified {
		t.Fatalf("exe should still be verified: %+v", it)
	}
}

func TestAWrongHashIsRefusedAndLeavesNothingBehind(t *testing.T) {
	r := newRelease()
	r.files[FileName(EXE, ver)+".sha256"] = []byte(strings.Repeat("0", 64) + "  x\n")
	s := newService(t, r)
	err := s.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a mismatching hash was accepted: %v", err)
	}
	if _, ok := s.Get(EXE); ok {
		t.Fatal("the damaged exe is offered")
	}
	if _, ok := s.Get(MSI); !ok {
		t.Fatal("the good msi should still be offered")
	}
	if s.Ready() {
		t.Fatal("ready with one installer missing")
	}
	if _, err := os.Stat(filepath.Join(s.versionDir(), FileName(EXE, ver))); err == nil {
		t.Fatal("the damaged file was kept")
	}
	if st := s.Status(); st.Error == "" {
		t.Fatal("the console should be told why")
	}
}

func TestStoredFilesAreNotFetchedAgainUnlessDamaged(t *testing.T) {
	r := newRelease()
	s := newService(t, r)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := r.hits[FileName(EXE, ver)]; n != 1 {
		t.Fatalf("the exe was downloaded %d times", n)
	}
	// A restart: a new Service on the same folder reuses the files.
	s2 := &Service{Dir: s.Dir, Version: ver, BaseURL: s.BaseURL, AllowHTTP: true}
	if err := s2.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := r.hits[FileName(EXE, ver)]; n != 1 {
		t.Fatalf("after a restart the exe was downloaded %d times", n)
	}
	// Damage one file on disk: it is fetched again.
	if err := os.WriteFile(filepath.Join(s.versionDir(), FileName(EXE, ver)), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s2.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := r.hits[FileName(EXE, ver)]; n != 2 {
		t.Fatalf("a damaged file should be fetched again, downloads = %d", n)
	}
	if it, _ := s2.Get(EXE); it.Size != int64(len("MZ exe bytes")) {
		t.Fatalf("the repaired file has size %d", it.Size)
	}
}

func TestMissingFilesReportAnErrorAndRetryLater(t *testing.T) {
	r := newRelease()
	delete(r.files, FileName(MSI, ver))
	s := newService(t, r)
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("a missing msi should be an error")
	}
	if _, ok := s.Get(EXE); !ok {
		t.Fatal("the exe should be offered even though the msi is not there yet")
	}
	r.add(FileName(MSI, ver), []byte("now published"), true)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.Ready() || s.Status().Error != "" {
		t.Fatal("not recovered after the file appeared")
	}
}

func TestReasonsItCannotWork(t *testing.T) {
	cases := map[string]*Service{
		"off":        {Dir: "/x", Version: ver, Off: true},
		"no dir":     {Version: ver},
		"dev build":  {Dir: "/x", Version: "0.1.0-dev"},
		"edge build": {Dir: "/x", Version: "0.0.0-edge.abcdef123456"},
		"no version": {Dir: "/x", Version: ""},
	}
	for name, s := range cases {
		if s.Enabled() {
			t.Errorf("%s: enabled", name)
		}
		if st := s.Status(); st.Enabled || st.Reason == "" || len(st.Items) != 0 {
			t.Errorf("%s: status %+v", name, st)
		}
		if err := s.Refresh(context.Background()); err == nil {
			t.Errorf("%s: refresh did not fail", name)
		}
	}
	var nilSvc *Service
	if nilSvc.Enabled() || nilSvc.Ready() || nilSvc.Status().Enabled {
		t.Error("a nil service must behave as disabled")
	}
	if _, ok := nilSvc.Get(MSI); ok {
		t.Error("a nil service has no files")
	}
	if !(&Service{Dir: "/x", Version: "1.2.3-rc1"}).Enabled() {
		t.Error("a release candidate is a release")
	}
}

func TestOnlyHTTPSAndSizeCapped(t *testing.T) {
	s := &Service{Dir: t.TempDir(), Version: ver}
	if _, err := s.get(context.Background(), "http://example.invalid/x", io.Discard, 10, false); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http accepted: %v", err)
	}
	r := newRelease()
	s2 := newService(t, r)
	if _, err := s2.get(context.Background(), s2.releaseURL(FileName(MSI, ver)), io.Discard, 100, false); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized download was accepted: %v", err)
	}
}

func TestOtherVersionsAreTidiedAway(t *testing.T) {
	s := newService(t, newRelease())
	old := filepath.Join(s.Dir, "1.0.0")
	if err := os.MkdirAll(old, 0o750); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(s.Dir, "notes")
	if err := os.MkdirAll(other, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("an older version's folder was kept")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("a folder that is not a version must be left alone")
	}
}

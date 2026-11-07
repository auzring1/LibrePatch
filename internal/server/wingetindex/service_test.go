package wingetindex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func TestRefreshStoresLoadsAndSkipsWhenFresh(t *testing.T) {
	db := pgtest.New(t)
	body := fixture(t)
	var hits, conditional atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	s := &Service{Pool: db.Pool, URL: srv.URL, AllowHTTP: true, Now: func() time.Time { return now }}
	ctx := context.Background()

	if s.Matcher() != nil {
		t.Fatal("a matcher before any download")
	}
	st, _ := s.Status(ctx)
	if st.PackageCount != 0 || st.FetchedAt != nil {
		t.Fatalf("fresh status: %+v", st)
	}
	updated, err := s.Refresh(ctx, false)
	if err != nil || !updated || s.Matcher() == nil || s.Matcher().Len() != 711 {
		t.Fatalf("first refresh: %v %v", updated, err)
	}
	// Fresh enough: no request at all.
	if updated, err := s.Refresh(ctx, false); err != nil || updated || hits.Load() != 1 {
		t.Fatalf("second refresh: %v %v hits=%d", updated, err, hits.Load())
	}
	// A day later the server asks again, conditionally, and keeps what it has.
	now = now.Add(25 * time.Hour)
	if updated, err := s.Refresh(ctx, false); err != nil || updated || conditional.Load() != 1 {
		t.Fatalf("conditional refresh: %v %v cond=%d", updated, err, conditional.Load())
	}
	st, _ = s.Status(ctx)
	if st.PackageCount != 711 || st.Error != "" || st.FetchedAt == nil || !st.FetchedAt.Equal(now) || st.SourceUpdated == nil {
		t.Fatalf("status: %+v", st)
	}

	// After a restart the stored copy is enough, with no network.
	s2 := &Service{Pool: db.Pool, URL: "http://127.0.0.1:1", AllowHTTP: true, Now: s.Now}
	if err := s2.Load(ctx); err != nil || s2.Matcher() == nil || s2.Matcher().Len() != 711 {
		t.Fatalf("load: %v", err)
	}
	if _, ok := s2.Matcher().Find(Installed{Name: "Google Chrome", Publisher: "Google LLC", ItemKey: "Google Chrome", Source: "reg64"}); !ok {
		t.Fatal("the loaded index does not match")
	}
}

func TestRefreshFailureKeepsTheOldIndexAndSaysWhy(t *testing.T) {
	db := pgtest.New(t)
	good := fixture(t)
	var bad atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bad.Load() {
			_, _ = w.Write([]byte("<html>captive portal</html>"))
			return
		}
		_, _ = w.Write(good)
	}))
	defer srv.Close()
	s := &Service{Pool: db.Pool, URL: srv.URL, AllowHTTP: true}
	ctx := context.Background()
	if _, err := s.Refresh(ctx, true); err != nil {
		t.Fatal(err)
	}
	bad.Store(true)
	if updated, err := s.Refresh(ctx, true); err == nil || updated {
		t.Fatalf("a page that is not an index was accepted: %v %v", updated, err)
	}
	if s.Matcher() == nil || s.Matcher().Len() != 711 {
		t.Fatal("the old index was dropped")
	}
	st, _ := s.Status(ctx)
	if st.Error == "" || st.PackageCount != 711 {
		t.Fatalf("status: %+v", st)
	}
	// An address that is not https is refused outright.
	s3 := &Service{Pool: db.Pool, URL: "http://example.org/x.msix"}
	if _, err := s3.Refresh(ctx, true); err == nil {
		t.Fatal("plain http accepted")
	}
}

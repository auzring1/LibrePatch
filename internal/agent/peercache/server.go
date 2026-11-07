package peercache

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// MaxConcurrent is how many files one agent sends at the same time. A computer that shares must stay usable for its user.
const MaxConcurrent = 2

// Server answers GET /v1/content/<sha256 hex> for files in the cache, to other devices of the installation on the same network.
type Server struct {
	Cache *Cache
	TLS   *tls.Config
	// Allow reports whether a client address may be served (the same network as one of this computer's interfaces).
	Allow func(net.IP) bool
	Log   *slog.Logger

	slots chan struct{}
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Handler is the HTTP handler (exported for tests).
func (s *Server) Handler() http.Handler {
	if s.slots == nil {
		s.slots = make(chan struct{}, MaxConcurrent)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/content/", s.serve)
	return mux
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip == nil || s.Allow == nil || !s.Allow(ip) {
		http.Error(w, "not on this network", http.StatusForbidden)
		return
	}
	sha, err := ParseName(strings.TrimPrefix(r.URL.Path, "/v1/content/"))
	if err != nil || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	f, err := s.Cache.Open(sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "30")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	st, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// A large file takes long; give each request a generous but bounded time to finish.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Hour))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "", st.ModTime(), f)
	s.log().Debug("peer download served", "to", host, "size", st.Size())
}

// Serve listens on addr until ctx ends. A listen error (port in use) is returned.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener serves on an existing listener.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), TLSConfig: s.TLS, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 8 << 10}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			_ = srv.Close()
		}
	}()
	err := srv.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

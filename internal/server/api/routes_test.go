package api

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// TestRoutesMatchSpec keeps the router and api/openapi.yaml in lockstep:
// every implemented route is documented and every documented route exists.
func TestRoutesMatchSpec(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var documented []string
	for p, ops := range spec.Paths {
		for m := range ops {
			switch m {
			case "get", "post", "put", "patch", "delete":
				documented = append(documented, strings.ToUpper(m)+" "+p)
			}
		}
	}

	s := &server{}
	r := chi.NewRouter()
	s.routes(r)
	var implemented []string
	if err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		implemented = append(implemented, method+" "+route)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	slices.Sort(documented)
	slices.Sort(implemented)
	for _, d := range documented {
		if !slices.Contains(implemented, d) {
			t.Errorf("documented but not implemented: %s", d)
		}
	}
	for _, i := range implemented {
		if !slices.Contains(documented, i) {
			t.Errorf("implemented but not documented: %s", i)
		}
	}
}

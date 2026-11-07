package e2e

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func parseUUID(t testing.TB, s string) uuid.UUID {
	t.Helper()
	u, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

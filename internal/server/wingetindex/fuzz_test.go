package wingetindex

import (
	"os"
	"testing"
)

// The index is downloaded from the network and parsed by a hand-written reader, so no input may panic it.
func FuzzParseDB(f *testing.F) {
	f.Add(seedDB(f))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseDB(b) })
}

func seedDB(f *testing.F) []byte {
	f.Helper()
	b, err := os.ReadFile("testdata/mini-source2.msix")
	if err != nil {
		f.Fatal(err)
	}
	db, err := extractDB(b)
	if err != nil {
		f.Fatal(err)
	}
	return db
}

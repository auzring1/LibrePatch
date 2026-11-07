package kek

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := s.Seal(PurposeTOTP, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := s.Open(PurposeTOTP, ct)
	if err != nil || !bytes.Equal(pt, []byte("secret")) {
		t.Fatalf("round trip failed: %v %q", err, pt)
	}
}

func TestOpenRejectsWrongPurposeTamperAndKey(t *testing.T) {
	s, _ := New(newKey(t))
	ct, _ := s.Seal(PurposeTOTP, []byte("secret"))
	if _, err := s.Open(PurposeIssuingKey, ct); err == nil {
		t.Fatal("expected purpose mismatch to fail")
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	if _, err := s.Open(PurposeTOTP, bad); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
	other, _ := New(newKey(t))
	if _, err := other.Open(PurposeTOTP, ct); err == nil {
		t.Fatal("expected wrong key to fail")
	}
	if _, err := s.Open(PurposeTOTP, []byte{1, 2}); err == nil {
		t.Fatal("expected short input to fail")
	}
}

func TestNewRejectsBadKeyLength(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("expected error")
	}
}

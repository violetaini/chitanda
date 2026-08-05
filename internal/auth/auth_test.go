package auth

import (
	"strings"
	"testing"
	"time"
)

func TestSignatureVerification(t *testing.T) {
	psk := []byte(strings.Repeat("k", 32))
	now := time.Unix(1_700_000_000, 0)
	ts := "1700000000"
	sig := Signature(psk, "POST", "/stream", "example.com:443", ts, "nonce")
	if !Verify(psk, "POST", "/stream", "example.com:443", ts, "nonce", sig, now) {
		t.Fatal("valid signature rejected")
	}
	if Verify(psk, "POST", "/stream", "other.example:443", ts, "nonce", sig, now) {
		t.Fatal("signature accepted for a different target")
	}
}

func TestReplayCache(t *testing.T) {
	cache := NewReplayCache()
	now := time.Unix(1_700_000_000, 0)
	if !cache.Accept("nonce", now) {
		t.Fatal("first nonce rejected")
	}
	if cache.Accept("nonce", now) {
		t.Fatal("replayed nonce accepted")
	}
	if !cache.Accept("nonce", now.Add(4*MaxClockSkew)) {
		t.Fatal("expired nonce was not removed")
	}
}

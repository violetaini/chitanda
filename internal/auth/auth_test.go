package auth

import (
	"os"
	"path/filepath"
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
	if accepted, err := cache.Accept("nonce", now); err != nil || !accepted {
		t.Fatal("first nonce rejected")
	}
	if accepted, err := cache.Accept("nonce", now); err != nil || accepted {
		t.Fatal("replayed nonce accepted")
	}
	if accepted, err := cache.Accept("nonce", now.Add(4*MaxClockSkew)); err != nil || !accepted {
		t.Fatal("expired nonce was not removed")
	}
}

func TestReplayCacheSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	now := time.Unix(1_700_000_000, 0)
	cache, err := OpenReplayCache(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := cache.Accept("persistent-nonce", now); err != nil || !accepted {
		t.Fatalf("first nonce: accepted=%v err=%v", accepted, err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenReplayCache(path, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if accepted, err := reopened.Accept("persistent-nonce", now.Add(time.Second)); err != nil || accepted {
		t.Fatalf("replayed nonce after restart: accepted=%v err=%v", accepted, err)
	}
}

func TestReplayCacheCompactionPreservesActiveNonces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	now := time.Unix(1_700_000_000, 0)
	cache, err := OpenReplayCache(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := cache.Accept("before-compaction", now); err != nil || !accepted {
		t.Fatalf("first nonce: accepted=%v err=%v", accepted, err)
	}
	cache.writesSince = replayCompactAfter
	if accepted, err := cache.Accept("after-compaction", now.Add(time.Second)); err != nil || !accepted {
		t.Fatalf("second nonce: accepted=%v err=%v", accepted, err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenReplayCache(path, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, nonce := range []string{"before-compaction", "after-compaction"} {
		if accepted, err := reopened.Accept(nonce, now.Add(2*time.Second)); err != nil || accepted {
			t.Fatalf("nonce %q after compaction: accepted=%v err=%v", nonce, accepted, err)
		}
	}
}

func TestPersistentReplayCacheStaysFailClosedAfterCompactionFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "replay.log")
	cache, err := OpenReplayCache(path, now)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	invalidTarget := filepath.Join(filepath.Dir(path), "rename-target")
	if err := os.Mkdir(invalidTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	cache.path = invalidTarget
	cache.writesSince = replayCompactAfter

	if accepted, err := cache.Accept("first-after-failure", now); err == nil || accepted {
		t.Fatalf("first accept after compaction failure: accepted=%v err=%v", accepted, err)
	}
	if accepted, err := cache.Accept("second-after-failure", now); err == nil || accepted {
		t.Fatalf("second accept after compaction failure: accepted=%v err=%v", accepted, err)
	}
}

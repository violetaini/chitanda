package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"myxray/internal/auth"
)

func TestServerAuthorizationAndReplay(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes
	replays := auth.NewReplayCache()
	defer replays.Close()

	fallbackCalled := false
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusNotFound)
	})

	srv := NewServer("/test-path-12345678", psk, replays, fallback, 1024)

	// 1. Test invalid path -> fallback
	req := httptest.NewRequest(http.MethodPost, "/wrong-path", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !fallbackCalled {
		t.Fatalf("expected fallback for wrong path")
	}
	fallbackCalled = false

	// 2. Test valid signature
	target := "1.1.1.1:80"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "test-nonce-1"
	sig := auth.Signature(psk, modeTCPv2, http.MethodPost, "/test-path-12345678", target, ts, nonce)

	req = httptest.NewRequest(http.MethodPost, "/test-path-12345678", nil)
	req.ProtoMajor = 2
	req.Header.Set(headerMode, modeTCPv2)
	req.Header.Set(headerTarget, target)
	req.Header.Set(headerTimestamp, ts)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, sig)

	// Authorize call
	err := srv.authorize(req, target, ts, nonce, sig)
	if err != nil {
		t.Fatalf("expected authorization success, got: %v", err)
	}

	// 3. Test replay of same nonce -> should return errReplayDetected
	err = srv.authorize(req, target, ts, nonce, sig)
	if err != errReplayDetected {
		t.Fatalf("expected errReplayDetected, got: %v", err)
	}

	// 4. Test replay in ServeHTTP -> should return 400 Bad Request directly without fallback
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if fallbackCalled {
		t.Fatalf("expected replay not to trigger fallback")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for replay, got: %d", w.Code)
	}
}

func TestStrictSNI(t *testing.T) {
	cfg := newTLSConfig("example.com")
	if cfg.GetConfigForClient == nil {
		t.Fatalf("expected GetConfigForClient to be configured")
	}

	// Test correct SNI
	chi := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}
	_, err := cfg.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("expected correct SNI to pass, got: %v", err)
	}

	// Test uppercase / lowercase matching
	chi = &tls.ClientHelloInfo{
		ServerName: "EXAMPLE.COM",
	}
	_, err = cfg.GetConfigForClient(chi)
	if err != nil {
		t.Fatalf("expected case-insensitive SNI to pass, got: %v", err)
	}
}

func TestCarrierProbe(t *testing.T) {
	srv := NewServer("/test-path", []byte(strings.Repeat("p", 32)), nil, nil, 1024)
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	req.Header.Set("X-Carrier-Probe", "1")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for carrier probe, got %d", w.Code)
	}
	if w.Header().Get(headerSessionOK) != "1" {
		t.Fatalf("expected X-Session-OK header on probe response")
	}
}

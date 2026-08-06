package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFallbackStripsPrivateHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	fallback, err := newFallback(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &server{fallback: fallback}
	request := httptest.NewRequest(http.MethodGet, "https://example.test/probe", nil)
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature} {
		request.Header.Set(name, "private-value")
	}
	response := httptest.NewRecorder()

	app.serveFallback(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	headers := <-seen
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature} {
		if value := headers.Get(name); value != "" {
			t.Fatalf("%s leaked to fallback", name)
		}
	}
}

func TestTLSConfigSupportsOrdinaryTLS12Fallback(t *testing.T) {
	config := newTLSConfig()
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x", config.MinVersion)
	}
	if len(config.NextProtos) < 2 || config.NextProtos[0] != "h2" || config.NextProtos[1] != "http/1.1" {
		t.Fatalf("ALPN protocols = %v", config.NextProtos)
	}
}

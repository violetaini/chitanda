package sessioncache

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCachePersistsSessionState(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	path := filepath.Join(t.TempDir(), "sessions.json")
	cache, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	firstTransport := newTestTransport(cache)
	request(t, &http.Client{Transport: firstTransport}, server.URL)
	firstTransport.CloseIdleConnections()
	deadline := time.Now().Add(time.Second)
	for !cache.HasEntries() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cache.HasEntries() {
		t.Fatal("TLS handshake did not store a session")
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	secondTransport := newTestTransport(reopened)
	response := request(t, &http.Client{Transport: secondTransport}, server.URL)
	secondTransport.CloseIdleConnections()
	if response.TLS == nil || !response.TLS.DidResume {
		t.Fatal("second TLS connection did not resume from the disk cache")
	}
	if err := reopened.Err(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Clear(); err != nil {
		t.Fatal(err)
	}
	empty, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if empty.HasEntries() {
		t.Fatal("cleared cache was restored from disk")
	}
}

func newTestTransport(cache tls.ClientSessionCache) *http.Transport {
	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			ClientSessionCache: cache,
		},
	}
}

func request(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response
}

package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fallbackObservation struct {
	header        http.Header
	body          string
	contentLength int64
}

type closeObservingBody struct {
	closed atomic.Bool
}

func (*closeObservingBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *closeObservingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestFallbackStripsPrivateHeaders(t *testing.T) {
	seen := make(chan fallbackObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- fallbackObservation{header: r.Header.Clone(), body: string(body), contentLength: r.ContentLength}
		w.Header().Set(headerSessionOK, "1")
		w.Header().Set(headerFraming, "1")
		w.Header().Set("X-Session-Early", "1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	fallback, err := newFallback(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &server{fallback: fallback}
	request := httptest.NewRequest(http.MethodPost, "https://example.test/probe", strings.NewReader("private-open-and-data"))
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature, headerMode} {
		request.Header.Set(name, "private-value")
	}
	response := httptest.NewRecorder()

	app.serveFallback(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	observation := <-seen
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature, headerMode} {
		if value := observation.header.Get(name); value != "" {
			t.Fatalf("%s leaked to fallback", name)
		}
	}
	if observation.body != "" || observation.contentLength != 0 {
		t.Fatalf("private body reached fallback: body=%q content_length=%d", observation.body, observation.contentLength)
	}
	for _, name := range []string{headerSessionOK, headerFraming, "X-Session-Early"} {
		if value := response.Header().Get(name); value != "" {
			t.Fatalf("fallback response leaked private marker %s=%q", name, value)
		}
	}
}

func TestFallbackPreservesOrdinaryRequestBody(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	fallback, err := newFallback(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &server{fallback: fallback}
	request := httptest.NewRequest(http.MethodPost, "https://example.test/upload", strings.NewReader("ordinary-body"))
	response := httptest.NewRecorder()
	app.serveFallback(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	if body := <-seen; body != "ordinary-body" {
		t.Fatalf("ordinary fallback body = %q", body)
	}
}

func TestFallbackTreatsEmptyPrivateHeaderAsPrivateAttempt(t *testing.T) {
	seen := make(chan fallbackObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- fallbackObservation{header: r.Header.Clone(), body: string(body), contentLength: r.ContentLength}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	fallback, err := newFallback(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &server{fallback: fallback}
	request := httptest.NewRequest(http.MethodPost, "https://example.test/probe", strings.NewReader("private-body"))
	request.Header[headerMode] = []string{""}
	response := httptest.NewRecorder()
	app.serveFallback(response, request)

	observation := <-seen
	if observation.body != "" || observation.contentLength != 0 {
		t.Fatalf("empty private header did not suppress fallback body: body=%q content_length=%d", observation.body, observation.contentLength)
	}
}

func TestFallbackDoesNotSynchronouslyClosePrivateBody(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != http.NoBody {
			t.Fatal("private body was not replaced")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	body := &closeObservingBody{}
	request := httptest.NewRequest(http.MethodPost, "https://example.test/probe", nil)
	request.Body = body
	request.ContentLength = 1
	request.Header.Set(headerMode, modeTCPv2)
	response := httptest.NewRecorder()

	(&server{fallback: fallback}).serveFallback(response, request)
	if body.closed.Load() {
		t.Fatal("private request body was synchronously closed")
	}
	if got := response.Header().Get("Connection"); got != "close" {
		t.Fatalf("Connection = %q, want close", got)
	}
}

func TestFallbackReleasesIncompleteHTTP1Body(t *testing.T) {
	app := &server{
		path: "/private",
		fallback: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	public := httptest.NewServer(app)
	defer public.Close()

	connection, err := net.Dial("tcp", strings.TrimPrefix(public.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := "POST /private HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		headerMode + ": " + modeTCPv2 + "\r\n\r\n" +
		"5\r\nx"
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 204 ") {
		t.Fatalf("status line = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("connection remained open after private fallback: %v", err)
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

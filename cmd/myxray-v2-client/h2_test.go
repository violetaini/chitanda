package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"myxray/internal/auth"
	"myxray/internal/frame"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type gatedResponseBody struct {
	prefix  *bytes.Reader
	end     <-chan struct{}
	closed  chan struct{}
	closeMu sync.Once
}

func (b *gatedResponseBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	select {
	case <-b.end:
		return 0, io.EOF
	case <-b.closed:
		return 0, net.ErrClosed
	}
}

func (b *gatedResponseBody) Close() error {
	b.closeMu.Do(func() { close(b.closed) })
	return nil
}

func TestH2OpenTCPRequiresAuthenticatedSuccessMarker(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	client := &h2Client{
		psk:        psk,
		path:       "/private-test-path",
		requestURL: "https://example.test/private-test-path",
	}
	client.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if !auth.Verify(psk, request.Method, request.URL.Path, request.Header.Get(headerTarget), request.Header.Get(headerTimestamp), request.Header.Get(headerNonce), request.Header.Get(headerSignature), time.Now()) {
			t.Fatal("request signature did not verify")
		}
		headers := make(http.Header)
		headers.Set(headerSessionOK, "1")
		headers.Set(headerFraming, "1")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     headers,
			Body:       io.NopCloser(strings.NewReader("response")),
		}, nil
	})}

	response, upload, err := client.openTCPOnce(context.Background(), "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = upload.Close()
	_ = response.Body.Close()
}

func TestH2OpenTCPRejectsMarkerWithoutFraming(t *testing.T) {
	client := &h2Client{
		psk:        []byte("0123456789abcdef0123456789abcdef"),
		path:       "/private-test-path",
		requestURL: "https://example.test/private-test-path",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			headers := make(http.Header)
			headers.Set(headerSessionOK, "1")
			return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader("site"))}, nil
		})},
	}
	if _, _, err := client.openTCPOnce(context.Background(), "1.1.1.1:443"); err == nil {
		t.Fatal("unframed carrier response was accepted")
	}
}

func TestH2OpenTCPRejectsFallbackHTTP200(t *testing.T) {
	client := &h2Client{
		psk:        []byte("0123456789abcdef0123456789abcdef"),
		path:       "/private-test-path",
		requestURL: "https://example.test/private-test-path",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("site"))}, nil
		})},
	}
	if _, _, err := client.openTCPOnce(context.Background(), "1.1.1.1:443"); err == nil {
		t.Fatal("ordinary fallback response was accepted")
	}
}

func TestValidTCPTransport(t *testing.T) {
	for _, value := range []string{tcpTransportAuto, tcpTransportH2, tcpTransportH3} {
		if !validTCPTransport(value) {
			t.Fatalf("%q rejected", value)
		}
	}
	if validTCPTransport("quic") {
		t.Fatal("unknown TCP transport accepted")
	}
}

func TestDefaultTCPTransportUsesH2(t *testing.T) {
	if defaultTCPTransport != tcpTransportH2 {
		t.Fatalf("default TCP transport = %q, want %q", defaultTCPTransport, tcpTransportH2)
	}
}

func TestH2OpenTCPHonorsCanceledContext(t *testing.T) {
	client := &h2Client{
		psk:        []byte("0123456789abcdef0123456789abcdef"),
		path:       "/private-test-path",
		requestURL: "https://example.test/private-test-path",
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, _, err := client.OpenTCP(ctx, "1.1.1.1:443"); err == nil {
		t.Fatal("canceled carrier attempt succeeded")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("canceled carrier attempt took %s", elapsed)
	}
}

func TestForwardH2TCPWaitsForCarrierEndStream(t *testing.T) {
	var terminal bytes.Buffer
	if err := frame.WriteFrame(&terminal, frame.TypeHalfClose, 0, nil); err != nil {
		t.Fatal(err)
	}
	endStream := make(chan struct{})
	body := &gatedResponseBody{
		prefix: bytes.NewReader(terminal.Bytes()),
		end:    endStream,
		closed: make(chan struct{}),
	}
	response := &http.Response{Body: body, Header: http.Header{headerFraming: []string{"1"}}}
	uploadReader, uploadWriter := io.Pipe()
	wantUpload := bytes.Repeat([]byte("payload"), 4096)
	uploadRead := make(chan []byte, 1)
	go func() {
		value, _ := io.ReadAll(uploadReader)
		uploadRead <- value
	}()

	proxySide, appSide := net.Pipe()
	defer appSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	client := &proxyClient{}
	go func() {
		client.forwardH2TCP(proxySide, bytes.NewReader(wantUpload), response, uploadWriter, cancel)
		close(done)
	}()

	var reply [10]byte
	if _, err := io.ReadFull(appSide, reply[:]); err != nil {
		t.Fatal(err)
	}
	if got := <-uploadRead; !bytes.Equal(got, wantUpload) {
		t.Fatalf("upload length = %d, want %d", len(got), len(wantUpload))
	}
	select {
	case <-done:
		t.Fatal("forwarder returned before HTTP/2 END_STREAM")
	case <-body.closed:
		t.Fatal("response body closed before HTTP/2 END_STREAM")
	case <-time.After(50 * time.Millisecond):
	}

	close(endStream)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not finish after HTTP/2 END_STREAM")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("response body was not closed")
	}
	if ctx.Err() == nil {
		t.Fatal("forwarding context was not canceled")
	}
}

func TestReadOpenAck(t *testing.T) {
	var valid bytes.Buffer
	if err := frame.WriteFrame(&valid, frame.TypeOpenAck, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := readOpenAck(&valid); err != nil {
		t.Fatalf("valid OPEN_ACK rejected: %v", err)
	}

	var invalid bytes.Buffer
	if err := frame.WriteFrame(&invalid, frame.TypeData, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := readOpenAck(&invalid); err == nil {
		t.Fatal("non-OPEN_ACK frame accepted")
	}

	var flagged bytes.Buffer
	if err := frame.WriteFrame(&flagged, frame.TypeOpenAck, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err := readOpenAck(&flagged); err == nil {
		t.Fatal("flagged OPEN_ACK accepted")
	}
}

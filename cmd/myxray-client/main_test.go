package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOpenStreamRetriesBeforeApplicationData(t *testing.T) {
	calls := 0
	c := &client{
		psk:        []byte("01234567890123456789012345678901"),
		path:       "/private-test-path",
		requestURL: "https://example.test/private-test-path",
		httpClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return nil, io.ErrUnexpectedEOF
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		})},
	}

	response, upload, err := c.openStream("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	defer upload.Close()
	if calls != 2 {
		t.Fatalf("transport calls = %d, want 2", calls)
	}
}

func TestHTTP2TransportAdvertisesLargeStreamWindow(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return clientConn, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTripDone := make(chan error, 1)
	go func() {
		_, err := transport.RoundTrip(request)
		roundTripDone <- err
	}()

	_ = serverConn.SetReadDeadline(time.Now().Add(time.Second))
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(serverConn, preface); err != nil {
		t.Fatal(err)
	}
	if string(preface) != http2.ClientPreface {
		t.Fatalf("unexpected HTTP/2 client preface")
	}
	frame, err := http2.NewFramer(serverConn, serverConn).ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("first frame is %T, want SETTINGS", frame)
	}
	var streamWindow uint32
	if err := settings.ForeachSetting(func(setting http2.Setting) error {
		if setting.ID == http2.SettingInitialWindowSize {
			streamWindow = setting.Val
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if streamWindow != 16<<20 {
		t.Fatalf("initial stream window = %d, want %d", streamWindow, 16<<20)
	}

	_ = serverConn.Close()
	cancel()
	<-roundTripDone
}

func TestNegotiateSOCKSPreservesBufferedPayload(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()

	peerDone := make(chan error, 1)
	go func() {
		if _, err := peer.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			peerDone <- err
			return
		}
		method := make([]byte, 2)
		if _, err := io.ReadFull(peer, method); err != nil {
			peerDone <- err
			return
		}
		requestAndPayload := append(
			[]byte{0x05, 0x01, 0x00, 0x03, 0x0b},
			[]byte("example.com")...,
		)
		requestAndPayload = append(requestAndPayload, 0x01, 0xbb)
		requestAndPayload = append(requestAndPayload, []byte("hello")...)
		_, err := peer.Write(requestAndPayload)
		peerDone <- err
	}()

	target, buffered, err := negotiateSOCKS(server)
	if err != nil {
		t.Fatal(err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q", target)
	}
	payload := make([]byte, 5)
	if _, err := io.ReadFull(buffered, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("payload = %q", payload)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

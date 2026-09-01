package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/http2"

	"chitanda/internal/auth"
	"chitanda/internal/socks5"
)

type h2Client struct {
	psk        []byte
	path       string
	rootURL    string
	requestURL string
	client     *http.Client
	transport  *http.Transport
}

func newH2Client(server, serverName, path string, psk []byte) (*h2Client, error) {
	port := portOf(server)
	rootURL := "https://" + net.JoinHostPort(serverName, port) + "/"
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     3 * time.Minute,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: serverName,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, network, server)
		},
	}
	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}
	h2Transport.ReadIdleTimeout = 45 * time.Second
	h2Transport.PingTimeout = 15 * time.Second
	return &h2Client{
		psk:        psk,
		path:       path,
		rootURL:    rootURL,
		requestURL: rootURL[:len(rootURL)-1] + path,
		client:     &http.Client{Transport: transport},
		transport:  transport,
	}, nil
}

func (c *h2Client) Prewarm(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, c.rootURL, nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *h2Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

func (c *h2Client) OpenTCP(ctx context.Context, target string) (*http.Response, *io.PipeWriter, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		response, upload, err := c.openTCPOnce(ctx, target)
		if err == nil {
			return response, upload, nil
		}
		lastErr = err
		if attempt == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, nil, ctx.Err()
			}
		}
	}
	return nil, nil, lastErr
}

func (c *h2Client) openTCPOnce(ctx context.Context, target string) (*http.Response, *io.PipeWriter, error) {
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.requestURL, reader)
	if err != nil {
		_ = writer.CloseWithError(err)
		return nil, nil, err
	}
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		_ = writer.CloseWithError(err)
		return nil, nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(headerMode, modeTCPH2Framed)
	request.Header.Set(headerTarget, target)
	request.Header.Set(headerTimestamp, timestamp)
	request.Header.Set(headerNonce, nonce)
	request.Header.Set(headerSignature, auth.Signature(c.psk, modeTCPH2Framed, request.Method, c.path, target, timestamp, nonce))

	response, err := c.client.Do(request)
	if err != nil {
		_ = writer.CloseWithError(err)
		return nil, nil, err
	}
	if response.StatusCode != http.StatusOK ||
		response.Header.Get(headerSessionOK) != "1" ||
		response.Header.Get(headerFraming) != "1" {
		_ = response.Body.Close()
		err = errors.New("HTTP/2 TCP carrier rejected")
		_ = writer.CloseWithError(err)
		return nil, nil, err
	}
	return response, writer, nil
}

func (c *proxyClient) handleTCP(local net.Conn, request socks5.Request) {
	if c.h2 != nil {
		ctx, cancel := context.WithCancel(context.Background())
		connectTimeout := carrierConnectTimeout
		if c.tcpTransport == tcpTransportAuto {
			connectTimeout = autoH2ConnectTimeout
		}
		connectTimer := time.AfterFunc(connectTimeout, cancel)
		response, upload, err := c.h2.OpenTCP(ctx, request.Target)
		if err == nil && connectTimer.Stop() {
			c.forwardH2TCP(local, request.Reader, response, upload, cancel)
			return
		}
		connectTimer.Stop()
		if err == nil {
			_ = response.Body.Close()
			_ = upload.CloseWithError(context.DeadlineExceeded)
		}
		cancel()
		if c.tcpTransport == tcpTransportH2 {
			_ = socks5.WriteReply(local, 0x01, nil)
			return
		}
		log.Printf("HTTP/2 TCP carrier unavailable; falling back to HTTP/3")
	}
	c.handleTCPH3(local, request)
}

func (c *proxyClient) forwardH2TCP(local net.Conn, source io.Reader, response *http.Response, upload *io.PipeWriter, cancel context.CancelFunc) {
	defer cancel()
	defer response.Body.Close()
	if err := socks5.WriteReply(local, 0x00, nil); err != nil {
		_ = upload.CloseWithError(err)
		return
	}
	_ = local.SetDeadline(time.Time{})
	uploadDone := make(chan error, 1)
	go func() {
		_, uploadErr := io.Copy(upload, source)
		if uploadErr != nil {
			_ = upload.CloseWithError(uploadErr)
		} else {
			_ = upload.Close()
		}
		uploadDone <- uploadErr
	}()
	receiveErr := copyDataFramesToLocal(response.Body, local)
	if receiveErr != nil {
		_ = upload.CloseWithError(receiveErr)
		_ = local.Close()
		select {
		case <-uploadDone:
		case <-time.After(time.Second):
		}
		return
	}

	// HALF_CLOSE is an application frame. Keep reading until HTTP/2's real
	// END_STREAM arrives, otherwise closing Body can reset a request body whose
	// final DATA frames are still in flight.
	carrierDone := make(chan error, 1)
	go func() {
		_, carrierErr := io.Copy(io.Discard, response.Body)
		carrierDone <- carrierErr
	}()
	for uploadDone != nil || carrierDone != nil {
		select {
		case <-uploadDone:
			uploadDone = nil
		case carrierErr := <-carrierDone:
			carrierDone = nil
			if carrierErr != nil && uploadDone != nil {
				_ = upload.CloseWithError(carrierErr)
				_ = local.Close()
			}
		}
	}
	_ = local.Close()
}

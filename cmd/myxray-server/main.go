package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"myxray/internal/auth"
	"myxray/internal/target"
)

const (
	headerTarget    = "X-Session-Target"
	headerTimestamp = "X-Session-Time"
	headerNonce     = "X-Session-Nonce"
	headerSignature = "X-Session-Auth"

	h2ConnectionReceiveWindow = 64 << 20
	h2StreamReceiveWindow     = 16 << 20
)

type server struct {
	path     string
	psk      []byte
	replays  *auth.ReplayCache
	fallback http.Handler
}

func main() {
	listen := flag.String("listen", ":11322", "public TLS listen address")
	adminListen := flag.String("admin-listen", "127.0.0.1:18122", "local health listen address")
	certFile := flag.String("cert", "", "TLS certificate chain")
	keyFile := flag.String("key", "", "TLS private key")
	pskFile := flag.String("psk-file", "", "hex or base64url PSK file")
	privatePath := flag.String("path", "", "private HTTP path")
	pathFile := flag.String("path-file", "", "file containing the private HTTP path")
	replayFile := flag.String("replay-file", "/var/lib/myxray/replay.log", "durable replay cache file")
	quicListen := flag.String("quic-listen", "", "optional HTTP/3 UDP listen address")
	ticketKeyFile := flag.String("ticket-key-file", "", "32-byte hex or base64url HTTP/3 ticket key")
	fallbackURL := flag.String("fallback", "https://127.0.0.1:443", "normal HTTPS fallback")
	fallbackServerName := flag.String("fallback-server-name", "probe.chitanda.org", "fallback TLS server name")
	flag.Parse()

	path, err := loadPath(*privatePath, *pathFile)
	if err != nil || *certFile == "" || *keyFile == "" || *pskFile == "" {
		log.Fatal("cert, key, psk-file and a valid private path are required")
	}
	psk, err := auth.LoadPSK(*pskFile)
	if err != nil {
		log.Fatalf("load PSK: %v", err)
	}
	fallback, err := newFallback(*fallbackURL, *fallbackServerName)
	if err != nil {
		log.Fatalf("configure fallback: %v", err)
	}
	replays, err := auth.OpenReplayCache(*replayFile, time.Now())
	if err != nil {
		log.Fatalf("open replay cache: %v", err)
	}
	defer replays.Close()

	app := &server{path: path, psk: psk, replays: replays, fallback: fallback}
	public := &http.Server{
		Addr:              *listen,
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       3 * time.Minute,
		TLSConfig:         newTLSConfig(),
	}
	if err := http2.ConfigureServer(public, &http2.Server{
		MaxUploadBufferPerConnection: h2ConnectionReceiveWindow,
		MaxUploadBufferPerStream:     h2StreamReceiveWindow,
		IdleTimeout:                  3 * time.Minute,
	}); err != nil {
		log.Fatalf("configure HTTP/2 server: %v", err)
	}
	admin := &http.Server{Addr: *adminListen, Handler: healthHandler(), ReadHeaderTimeout: 2 * time.Second}
	var h3Server *http3.Server
	if *quicListen != "" {
		if *ticketKeyFile == "" {
			log.Fatal("ticket-key-file is required when quic-listen is enabled")
		}
		h3Server, err = newHTTP3Server(*quicListen, app, *ticketKeyFile, *certFile, *keyFile)
		if err != nil {
			log.Fatalf("configure HTTP/3 server: %v", err)
		}
	}

	go func() {
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server: %v", err)
		}
	}()
	if h3Server != nil {
		go func() {
			log.Printf("public HTTP/3 listener started on %s", *quicListen)
			if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP/3 server: %v", err)
			}
		}()
	}
	go func() {
		log.Printf("public TLS listener started on %s", *listen)
		if err := public.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("public server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = public.Shutdown(ctx)
	_ = admin.Shutdown(ctx)
	if h3Server != nil {
		_ = h3Server.Shutdown(ctx)
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 3 {
		s.serveHTTP3(w, r)
		return
	}
	if r.URL.Path != s.path || r.Method != http.MethodPost || r.ProtoMajor != 2 {
		s.serveFallback(w, r)
		return
	}
	targetAddress := r.Header.Get(headerTarget)
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	signature := r.Header.Get(headerSignature)
	if !s.authorize(r, targetAddress, timestamp, nonce, signature) {
		s.serveFallback(w, r)
		return
	}

	upstream, err := target.DialContext(r.Context(), targetAddress)
	if err != nil {
		log.Printf("authenticated upstream dial failed")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	go func() {
		_, _ = io.Copy(upstream, r.Body)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(flushWriter{w: w}, upstream)
}

func (s *server) authorize(r *http.Request, targetAddress, timestamp, nonce, signature string) bool {
	now := time.Now()
	if !auth.Verify(s.psk, r.Method, r.URL.Path, targetAddress, timestamp, nonce, signature, now) {
		return false
	}
	accepted, err := s.replays.Accept(nonce, now)
	if err != nil {
		log.Printf("replay cache unavailable")
	}
	return accepted && err == nil
}

func (s *server) serveFallback(w http.ResponseWriter, r *http.Request) {
	r.Header.Del(headerTarget)
	r.Header.Del(headerTimestamp)
	r.Header.Del(headerNonce)
	r.Header.Del(headerSignature)
	s.fallback.ServeHTTP(w, r)
}

type flushWriter struct {
	w http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if flusher, ok := w.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func newFallback(rawURL, serverName string) (http.Handler, error) {
	targetURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.NotFound(w, nil)
	}
	return proxy, nil
}

func newTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func validPath(path string) bool {
	return strings.HasPrefix(path, "/") && len(path) >= 16 && !strings.ContainsAny(path, "?#")
}

func loadPath(value, pathFile string) (string, error) {
	if value == "" && pathFile != "" {
		raw, err := os.ReadFile(pathFile)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(raw))
	}
	if !validPath(value) {
		return "", fmt.Errorf("invalid private path")
	}
	return value, nil
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lmsgprefix)
	log.SetPrefix("myxray-server: ")
}

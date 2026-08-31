package server

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"myxray/internal/auth"
	"myxray/internal/target"
)

var copyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 256<<10)
		return &b
	},
}

const (
	headerTarget    = "X-Session-Target"
	headerTimestamp = "X-Session-Time"
	headerNonce     = "X-Session-Nonce"
	headerSignature = "X-Session-Auth"
	headerMode      = "X-Session-Mode"
	headerSessionOK = "X-Session-OK"
	headerFraming   = "X-Session-Framing"
)

// Server implements the my_xray inbound handler
type Server struct {
	path            string
	psk             []byte
	replays         *auth.ReplayCache
	fallback        http.Handler
	udpTargetBuffer int
}

// NewServer creates a new Server instance
func NewServer(path string, psk []byte, replays *auth.ReplayCache, fallback http.Handler, udpTargetBuffer int) *Server {
	return &Server{
		path:            path,
		psk:             psk,
		replays:         replays,
		fallback:        fallback,
		udpTargetBuffer: udpTargetBuffer,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Carrier-Probe") == "1" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(headerSessionOK, "1")
		w.WriteHeader(http.StatusOK)
		return
	}
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
	if err := s.authorize(r, targetAddress, timestamp, nonce, signature); err != nil {
		if errors.Is(err, errReplayDetected) {
			// Fast-fail on replays to prevent DoS amplification (don't dial fallback)
			// Returning standard HTTP error mimics proxy error or fallback error 
			// without the huge cost of a real upstream TLS connection.
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
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
	w.Header().Set(headerSessionOK, "1")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	uploadDone := make(chan error, 1)
	go func() {
		bufPtr := copyBufferPool.Get().(*[]byte)
		defer copyBufferPool.Put(bufPtr)
		_, uploadErr := io.CopyBuffer(upstream, r.Body, *bufPtr)
		if uploadErr == nil {
			if tcp, ok := upstream.(*net.TCPConn); ok {
				uploadErr = tcp.CloseWrite()
			}
		} else {
			_ = upstream.Close()
		}
		uploadDone <- uploadErr
	}()
	var downloadErr error
	bufPtr := copyBufferPool.Get().(*[]byte)
	_, downloadErr = io.CopyBuffer(flushWriter{w: w}, upstream, *bufPtr)
	copyBufferPool.Put(bufPtr)
	if downloadErr != nil {
		_ = upstream.Close()
		return
	}
	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.CloseRead()
	}
	select {
	case <-uploadDone:
	case <-r.Context().Done():
	}
}

func (s *Server) authorize(r *http.Request, targetAddress, timestamp, nonce, signature string) error {
	mode := r.Header.Get(headerMode)
	if mode == "" {
		mode = modeTCPv2
	}
	now := time.Now()
	if !auth.Verify(s.psk, mode, r.Method, r.URL.Path, targetAddress, timestamp, nonce, signature, now) {
		return errInvalidSignature
	}
	accepted, err := s.replays.Accept(nonce, now)
	if err != nil {
		log.Printf("replay cache unavailable")
	}
	if !accepted || err != nil {
		return errReplayDetected
	}
	return nil
}

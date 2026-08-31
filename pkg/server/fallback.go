package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// NewFallback creates a reverse proxy to the fallback URL
func NewFallback(rawURL, serverName string) (http.Handler, error) {
	targetURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Del(headerSessionOK)
		response.Header.Del(headerFraming)
		response.Header.Del("X-Session-Early")
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.NotFound(w, nil)
	}
	return proxy, nil
}

func (s *Server) serveFallback(w http.ResponseWriter, r *http.Request) {
	privateAttempt := false
	for _, name := range []string{headerTarget, headerTimestamp, headerNonce, headerSignature, headerMode} {
		if _, present := r.Header[http.CanonicalHeaderKey(name)]; present {
			privateAttempt = true
		}
		r.Header.Del(name)
	}
	if privateAttempt {
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
			defer func() {
				_ = http.NewResponseController(w).SetReadDeadline(time.Unix(1, 0))
			}()
		}
		r.Body = http.NoBody
		r.GetBody = nil
		r.ContentLength = 0
		r.TransferEncoding = nil
		r.Trailer = nil
		r.Header.Del("Content-Length")
		r.Header.Del("Transfer-Encoding")
		r.Header.Del("Expect")
	}
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

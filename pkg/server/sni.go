package server

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
)

// newTLSConfig creates a strict SNI TLS configuration.
func newTLSConfig(strictSNI string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			// Strict SNI checking
			if strictSNI != "" {
				if !strings.EqualFold(chi.ServerName, strictSNI) {
					log.Printf("blocked connection from %v due to strict SNI mismatch: got %q, want %q", chi.Conn.RemoteAddr(), chi.ServerName, strictSNI)
					// Force TCP RST (not FIN) to prevent any TLS Alert from leaking
					if tc, ok := chi.Conn.(*net.TCPConn); ok {
						tc.SetLinger(0)
					}
					chi.Conn.Close()
					return nil, errors.New("strict SNI mismatch")
				}
			} else {
				// If strictSNI is not configured, we should still drop empty SNIs
				if chi.ServerName == "" {
					log.Printf("blocked connection from %v due to missing SNI", chi.Conn.RemoteAddr())
					if tc, ok := chi.Conn.(*net.TCPConn); ok {
						tc.SetLinger(0)
					}
					chi.Conn.Close()
					return nil, errors.New("missing SNI")
				}
			}
			return nil, nil
		},
	}
}

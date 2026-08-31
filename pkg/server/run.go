package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// Run starts the proxy server with the given configuration.
// It blocks until a termination signal is received.
func Run(config *Config, listenAddr, adminListenAddr, quicListenAddr string) error {
	path, psk, replays, err := config.Init()
	if err != nil {
		return err
	}
	defer replays.Close()

	fallback, err := NewFallback(config.FallbackURL, config.FallbackServerName)
	if err != nil {
		return err
	}

	app := NewServer(path, psk, replays, fallback, config.UDPTargetBuffer)

	public := &http.Server{
		Addr:              listenAddr,
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       3 * time.Minute,
		TLSConfig:         newTLSConfig(config.StrictSNI),
	}
	if err := http2.ConfigureServer(public, &http2.Server{
		MaxUploadBufferPerConnection: 15 * 1024 * 1024,
		MaxUploadBufferPerStream:     15 * 1024 * 1024,
		MaxReadFrameSize:             1 << 20,
		IdleTimeout:                  3 * time.Minute,
	}); err != nil {
		return err
	}

	admin := &http.Server{Addr: adminListenAddr, Handler: healthHandler(), ReadHeaderTimeout: 2 * time.Second}
	
	var h3Server *http3ServerWrapper
	if quicListenAddr != "" {
		if config.TicketKeyFile == "" {
			return errors.New("ticket-key-file is required when quic-listen is enabled")
		}
		hs, err := newHTTP3Server(quicListenAddr, app, config.TicketKeyFile, config.CertFile, config.KeyFile, config.QuicInitialPacketSize, config.StrictSNI)
		if err != nil {
			return err
		}
		h3Server = &http3ServerWrapper{Server: hs}
	}

	go func() {
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server: %v", err)
		}
	}()
	if h3Server != nil {
		go func() {
			log.Printf("public HTTP/3 listener started on %s", quicListenAddr)
			udpAddr, err := net.ResolveUDPAddr("udp", quicListenAddr)
			if err != nil {
				log.Fatalf("resolve HTTP/3 addr: %v", err)
			}
			udpConn, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				log.Fatalf("listen HTTP/3: %v", err)
			}
			_ = udpConn.SetReadBuffer(8 << 20)
			_ = udpConn.SetWriteBuffer(8 << 20)
			if err := h3Server.Serve(udpConn); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP/3 server: %v", err)
			}
		}()
	}
	// Plain-UDP listener (shares same port/address as listenAddr on UDP)
	if plainUDPAddr, err := net.ResolveUDPAddr("udp", listenAddr); err == nil {
		if plainUDPLn, err := net.ListenUDP("udp", plainUDPAddr); err == nil {
			_ = plainUDPLn.SetReadBuffer(8 << 20)
			_ = plainUDPLn.SetWriteBuffer(8 << 20)
			plainUDPServer := NewPlainUDPServer(plainUDPLn, psk)
			go func() {
				log.Printf("public plain-UDP datagram listener started on %s", listenAddr)
				_ = plainUDPServer.Serve(context.Background())
			}()
		}
	}

	go func() {
		if config.CertFile == "" || config.KeyFile == "" {
			log.Printf("public Plain HTTP/1.1 listener started on %s", listenAddr)
			if err := public.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("public plain server: %v", err)
			}
		} else {
			log.Printf("public TLS listener started on %s", listenAddr)
			if err := public.ListenAndServeTLS(config.CertFile, config.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("public server: %v", err)
			}
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
		_ = h3Server.Close()
	}
	return nil
}

type http3ServerWrapper struct {
	*http3.Server // from github.com/quic-go/quic-go/http3
}

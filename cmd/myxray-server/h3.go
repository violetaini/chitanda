package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"

	"myxray/internal/auth"
	"myxray/internal/frame"
	"myxray/internal/quicconfig"
	"myxray/internal/target"
)

const (
	headerMode  = "X-Session-Mode"
	modeTCPv2   = "tcp-v2"
	modeUDPv2   = "udp-v2"
	udpAuthName = "udp-association"
)

func newHTTP3Server(address string, handler http.Handler, ticketKeyFile, certFile, keyFile string) (*http3.Server, error) {
	ticketKey, err := auth.LoadPSK(ticketKeyFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], ticketKey[:32])
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	tlsConfig.SetSessionTicketKeys([][32]byte{key})
	return &http3.Server{
		Addr:            address,
		TLSConfig:       tlsConfig,
		QUICConfig:      quicconfig.Server(),
		Handler:         handler,
		EnableDatagrams: true,
		MaxHeaderBytes:  16 << 10,
		IdleTimeout:     3 * time.Minute,
	}, nil
}

func (s *server) serveHTTP3(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.path {
		s.serveFallback(w, r)
		return
	}
	targetAddress := r.Header.Get(headerTarget)
	timestamp := r.Header.Get(headerTimestamp)
	nonce := r.Header.Get(headerNonce)
	signature := r.Header.Get(headerSignature)
	switch {
	case r.Method == http.MethodGet && r.Header.Get(headerMode) == modeTCPv2:
		if !s.authorize(r, targetAddress, timestamp, nonce, signature) {
			s.serveFallback(w, r)
			return
		}
		s.serveHTTP3TCP(w, r, targetAddress)
	case r.Method == http.MethodConnect && r.Proto == "connect-udp" && r.Header.Get(headerMode) == modeUDPv2:
		if targetAddress != udpAuthName || !s.authorize(r, targetAddress, timestamp, nonce, signature) {
			s.serveFallback(w, r)
			return
		}
		s.serveHTTP3UDP(w, r)
	default:
		s.serveFallback(w, r)
	}
}

func (s *server) serveHTTP3TCP(w http.ResponseWriter, r *http.Request, targetAddress string) {
	upstream, err := target.DialContext(r.Context(), targetAddress)
	if err != nil {
		log.Printf("authenticated HTTP/3 upstream dial failed")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		w.Header().Set("X-Session-Early", "1")
	}
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return
	}
	stream := streamer.HTTPStream()
	defer stream.Close()

	uploadDone := make(chan error, 1)
	go func() {
		uploadErr := copyFramesToTCP(stream, upstream, targetAddress)
		if uploadErr != nil {
			_ = upstream.Close()
		}
		uploadDone <- uploadErr
	}()
	if err := frame.WriteFrame(stream, frame.TypeOpenAck, 0, nil); err != nil {
		return
	}
	_, _ = frame.CopyAsDataFrames(stream, upstream)
	_ = frame.WriteFrame(stream, frame.TypeHalfClose, 0, nil)
	<-uploadDone
}

func copyFramesToTCP(stream io.Reader, upstream net.Conn, targetAddress string) error {
	header, err := frame.ReadHeader(stream)
	if err != nil {
		return err
	}
	if header.Type != frame.TypeOpen {
		return errors.New("first private frame is not OPEN")
	}
	payload, err := frame.ReadPayload(stream, header.Length)
	if err != nil {
		return err
	}
	if string(payload) != targetAddress {
		return errors.New("OPEN target mismatch")
	}
	for {
		header, err := frame.ReadHeader(stream)
		if err != nil {
			return err
		}
		switch header.Type {
		case frame.TypeData:
			if _, err := io.CopyN(upstream, stream, int64(header.Length)); err != nil {
				return err
			}
		case frame.TypeHalfClose:
			if header.Length != 0 {
				return errors.New("HALF_CLOSE frame contains payload")
			}
			if tcp, ok := upstream.(*net.TCPConn); ok {
				return tcp.CloseWrite()
			}
			return nil
		case frame.TypeReset:
			return errors.New("peer reset stream")
		default:
			if _, err := io.CopyN(io.Discard, stream, int64(header.Length)); err != nil {
				return err
			}
		}
	}
}

func (s *server) serveHTTP3UDP(w http.ResponseWriter, r *http.Request) {
	settings, ok := w.(http3.Settingser)
	if !ok {
		http.Error(w, "HTTP datagrams unavailable", http.StatusBadRequest)
		return
	}
	select {
	case <-settings.ReceivedSettings():
	case <-r.Context().Done():
		return
	}
	peerSettings := settings.Settings()
	if !peerSettings.EnableDatagrams {
		http.Error(w, "HTTP datagrams unavailable", http.StatusBadRequest)
		return
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return
	}
	stream := streamer.HTTPStream()
	defer stream.Close()
	relay := newUDPRelay(r.Context(), stream)
	defer relay.Close()
	for {
		packet, err := stream.ReceiveDatagram(r.Context())
		if err != nil {
			if r.Context().Err() == nil {
				log.Printf("HTTP/3 UDP receive stopped: %v", err)
			}
			return
		}
		if err := relay.Forward(packet); err != nil {
			log.Printf("HTTP/3 UDP datagram rejected")
		}
	}
}

type datagramStream interface {
	SendDatagram([]byte) error
}

type udpTarget struct {
	address string
	conn    *net.UDPConn
}

type udpRelay struct {
	ctx       context.Context
	stream    datagramStream
	mu        sync.Mutex
	sendMu    sync.Mutex
	targets   map[string]*udpTarget
	replay    frame.ReplayWindow
	sequence  atomic.Uint64
	waitGroup sync.WaitGroup
}

func newUDPRelay(ctx context.Context, stream datagramStream) *udpRelay {
	return &udpRelay{ctx: ctx, stream: stream, targets: make(map[string]*udpTarget)}
}

func (r *udpRelay) Forward(packet []byte) error {
	sequence, address, payload, err := frame.DecodeDatagram(packet)
	if err != nil || !r.replay.Accept(sequence) {
		return errors.New("invalid or replayed datagram")
	}
	r.mu.Lock()
	targetConn := r.targets[address]
	r.mu.Unlock()
	if targetConn != nil {
		_, err = targetConn.conn.Write(payload)
		return err
	}
	resolved, err := target.ResolveUDPAddr(r.ctx, address)
	if err != nil {
		return err
	}
	r.mu.Lock()
	targetConn = r.targets[address]
	if targetConn == nil {
		if len(r.targets) >= 64 {
			r.mu.Unlock()
			return errors.New("too many UDP targets")
		}
		connection, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		targetConn = &udpTarget{address: address, conn: connection}
		r.targets[address] = targetConn
		r.waitGroup.Add(1)
		go r.receive(targetConn)
	}
	r.mu.Unlock()
	_, err = targetConn.conn.Write(payload)
	return err
}

func (r *udpRelay) receive(targetConn *udpTarget) {
	defer r.waitGroup.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, err := targetConn.conn.Read(buffer)
		if err != nil {
			return
		}
		if n > frame.MaxDatagramPayload {
			continue
		}
		packet, err := frame.EncodeDatagram(r.sequence.Add(1), targetConn.address, buffer[:n])
		if err != nil {
			continue
		}
		r.sendMu.Lock()
		err = r.stream.SendDatagram(packet)
		r.sendMu.Unlock()
		if err != nil {
			return
		}
	}
}

func (r *udpRelay) Close() {
	r.mu.Lock()
	for _, targetConn := range r.targets {
		_ = targetConn.conn.Close()
	}
	r.mu.Unlock()
	r.waitGroup.Wait()
}

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"myxray/internal/auth"
	"myxray/internal/frame"
	"myxray/internal/quicconfig"
	"myxray/internal/sessioncache"
	"myxray/internal/socks5"
)

const (
	headerTarget    = "X-Session-Target"
	headerTimestamp = "X-Session-Time"
	headerNonce     = "X-Session-Nonce"
	headerSignature = "X-Session-Auth"
	headerMode      = "X-Session-Mode"
	modeTCPv2       = "tcp-v2"
	modeUDPv2       = "udp-v2"
	udpAuthName     = "udp-association"
)

type connection struct {
	quic *quic.Conn
	h3   *http3.ClientConn
}

type manager struct {
	mu           sync.Mutex
	server       string
	serverName   string
	rootURL      string
	requestURL   string
	path         string
	psk          []byte
	tlsConfig    *tls.Config
	quicConfig   *quic.Config
	transport    *http3.Transport
	sessionCache *sessioncache.Cache
	current      *connection
}

type proxyClient struct {
	manager *manager
}

func main() {
	listen := flag.String("listen", "127.0.0.1:22081", "local SOCKS5 TCP and UDP control address")
	serverAddress := flag.String("server", "170.9.59.149:11322", "server UDP address")
	serverName := flag.String("server-name", "status.chitanda.org", "TLS server name")
	pskFile := flag.String("psk-file", "", "hex or base64url PSK file")
	privatePath := flag.String("path", "", "private HTTP path")
	pathFile := flag.String("path-file", "", "file containing the private HTTP path")
	sessionCacheFile := flag.String("session-cache-file", "", "persistent TLS session cache file")
	provisionOnly := flag.Bool("provision-only", false, "obtain a resumable HTTP/3 ticket and exit")
	quicInitialPacketSize := flag.Uint("quic-initial-packet-size", quicconfig.DefaultInitialPacketSize, "QUIC initial packet size (1200-1452)")
	flag.Parse()
	if *quicInitialPacketSize < quicconfig.MinInitialPacketSize || *quicInitialPacketSize > quicconfig.MaxInitialPacketSize {
		log.Fatal("quic-initial-packet-size must be between 1200 and 1452")
	}

	path, err := loadPath(*privatePath, *pathFile)
	if *pskFile == "" || *sessionCacheFile == "" || err != nil {
		log.Fatal("psk-file, session-cache-file and private path are required")
	}
	psk, err := auth.LoadPSK(*pskFile)
	if err != nil {
		log.Fatalf("load PSK: %v", err)
	}
	cache, err := sessioncache.Open(*sessionCacheFile)
	if err != nil {
		log.Fatalf("open session cache: %v", err)
	}
	port := portOf(*serverAddress)
	rootURL := "https://" + net.JoinHostPort(*serverName, port) + "/"
	mgr := &manager{
		server:       *serverAddress,
		serverName:   *serverName,
		rootURL:      rootURL,
		requestURL:   strings.TrimSuffix(rootURL, "/") + path,
		path:         path,
		psk:          psk,
		tlsConfig:    &tls.Config{MinVersion: tls.VersionTLS13, ServerName: *serverName, ClientSessionCache: cache, NextProtos: []string{http3.NextProtoH3}},
		quicConfig:   quicconfig.Client(uint16(*quicInitialPacketSize)),
		transport:    &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		sessionCache: cache,
	}
	if *provisionOnly {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := mgr.provision(ctx); err != nil {
			log.Fatal(err)
		}
		log.Printf("HTTP/3 resumption ticket persisted")
		return
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	client := &proxyClient{manager: mgr}
	log.Printf("V2 SOCKS5 TCP/UDP listener started on %s; ticket_cached=%v", *listen, cache.HasEntries())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = listener.Close()
		mgr.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go client.handleSOCKS(conn)
	}
}

func (m *manager) ensureConnection(ctx context.Context) (*connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil && m.current.quic.Context().Err() == nil {
		return m.current, nil
	}
	quicConn, err := quic.DialAddrEarly(ctx, m.server, m.tlsConfig.Clone(), m.quicConfig.Clone())
	if err != nil {
		return nil, err
	}
	m.current = &connection{quic: quicConn, h3: m.transport.NewClientConn(quicConn)}
	return m.current, nil
}

func (m *manager) invalidate(value *connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == value {
		_ = value.quic.CloseWithError(0, "reconnect")
		m.current = nil
	}
}

func (m *manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		_ = m.current.quic.CloseWithError(0, "shutdown")
		m.current = nil
	}
	_ = m.transport.Close()
}

func (m *manager) provision(ctx context.Context) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := m.ensureConnection(ctx)
		if err != nil {
			return err
		}
		select {
		case <-conn.quic.HandshakeComplete():
		case <-ctx.Done():
			return ctx.Err()
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodHead, m.rootURL, nil)
		if err != nil {
			return err
		}
		response, err := conn.h3.RoundTrip(request)
		if err == nil {
			_ = response.Body.Close()
			waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err = m.sessionCache.WaitForUpdate(waitCtx)
			cancel()
			if err == nil {
				return m.sessionCache.Err()
			}
		}
		lastErr = err
		if errors.Is(err, quic.Err0RTTRejected) {
			if clearErr := m.sessionCache.Clear(); clearErr != nil {
				return clearErr
			}
		}
		m.invalidate(conn)
	}
	return lastErr
}

func (m *manager) openTCP(ctx context.Context, target string) (*http3.RequestStream, *connection, error) {
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := m.ensureConnection(ctx)
		if err != nil {
			return nil, nil, err
		}
		stream, err := conn.h3.OpenRequestStream(ctx)
		if err == nil {
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, m.requestURL, nil)
			if requestErr != nil {
				return nil, nil, requestErr
			}
			err = m.sign(request, target, modeTCPv2)
			if err == nil {
				err = stream.SendRequestHeader(request)
			}
			if err == nil {
				err = frame.WriteFrame(stream, frame.TypeOpen, 0, []byte(target))
			}
		}
		if err == nil {
			return stream, conn, nil
		}
		if errors.Is(err, quic.Err0RTTRejected) {
			if clearErr := m.sessionCache.Clear(); clearErr != nil {
				return nil, nil, clearErr
			}
		}
		m.invalidate(conn)
		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, nil, errors.New("open HTTP/3 TCP stream failed")
}

func (m *manager) openUDP(ctx context.Context) (*http3.RequestStream, *connection, error) {
	conn, err := m.ensureConnection(ctx)
	if err != nil {
		return nil, nil, err
	}
	select {
	case <-conn.h3.ReceivedSettings():
	case <-conn.quic.Context().Done():
		return nil, conn, context.Cause(conn.quic.Context())
	case <-ctx.Done():
		return nil, conn, ctx.Err()
	}
	settings := conn.h3.Settings()
	if !settings.EnableDatagrams || !settings.EnableExtendedConnect {
		return nil, conn, errors.New("server did not enable HTTP datagrams")
	}
	stream, err := conn.h3.OpenRequestStream(ctx)
	if err != nil {
		return nil, conn, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodConnect, m.requestURL, nil)
	if err != nil {
		return nil, conn, err
	}
	request.Proto = "connect-udp"
	if err := m.sign(request, udpAuthName, modeUDPv2); err != nil {
		return nil, conn, err
	}
	if err := stream.SendRequestHeader(request); err != nil {
		return nil, conn, err
	}
	return stream, conn, nil
}

func (m *manager) sign(request *http.Request, target, mode string) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set(headerMode, mode)
	request.Header.Set(headerTarget, target)
	request.Header.Set(headerTimestamp, timestamp)
	request.Header.Set(headerNonce, nonce)
	request.Header.Set(headerSignature, auth.Signature(m.psk, request.Method, m.path, target, timestamp, nonce))
	return nil
}

func (c *proxyClient) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	request, err := socks5.Negotiate(conn)
	if err != nil {
		return
	}
	switch request.Command {
	case socks5.CommandConnect:
		c.handleTCP(conn, request)
	case socks5.CommandUDPAssociate:
		c.handleUDP(conn)
	}
}

func (c *proxyClient) handleTCP(local net.Conn, request socks5.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, h3Conn, err := c.manager.openTCP(ctx, request.Target)
	if err != nil {
		_ = socks5.WriteReply(local, 0x01, nil)
		return
	}
	if err := socks5.WriteReply(local, 0x00, nil); err != nil {
		return
	}
	_ = local.SetDeadline(time.Time{})
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, _ = frame.CopyAsDataFrames(stream, request.Reader)
		_ = frame.WriteFrame(stream, frame.TypeHalfClose, 0, nil)
		_ = stream.Close()
	}()
	response, err := stream.ReadResponse()
	if err != nil {
		c.manager.invalidate(h3Conn)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return
	}
	state := h3Conn.quic.ConnectionState()
	log.Printf("V2 TCP stream established: used_0rtt=%v early_accepted=%v", state.Used0RTT, response.Header.Get("X-Session-Early") == "1")
	if err := copyFramesToLocal(stream, local); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("V2 TCP receive failed")
	}
	_ = local.Close()
	<-uploadDone
}

func copyFramesToLocal(stream io.Reader, local net.Conn) error {
	header, err := frame.ReadHeader(stream)
	if err != nil {
		return err
	}
	if header.Type != frame.TypeOpenAck || header.Length != 0 {
		return errors.New("missing OPEN_ACK")
	}
	for {
		header, err := frame.ReadHeader(stream)
		if err != nil {
			return err
		}
		switch header.Type {
		case frame.TypeData:
			if _, err := io.CopyN(local, stream, int64(header.Length)); err != nil {
				return err
			}
		case frame.TypeHalfClose:
			if header.Length != 0 {
				return errors.New("HALF_CLOSE frame contains payload")
			}
			if tcp, ok := local.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			return nil
		case frame.TypeReset:
			return errors.New("server reset stream")
		default:
			if _, err := io.CopyN(io.Discard, stream, int64(header.Length)); err != nil {
				return err
			}
		}
	}
}

func (c *proxyClient) handleUDP(control net.Conn) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = socks5.WriteReply(control, 0x01, nil)
		return
	}
	defer udpConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stream *http3.RequestStream
	var h3Conn *connection
	var response *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		stream, h3Conn, err = c.manager.openUDP(ctx)
		if err == nil {
			_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			response, err = stream.ReadResponse()
			_ = stream.SetReadDeadline(time.Time{})
		}
		if err == nil {
			break
		}
		if stream != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
		if h3Conn != nil {
			if errors.Is(err, quic.Err0RTTRejected) {
				if clearErr := c.manager.sessionCache.Clear(); clearErr != nil {
					_ = socks5.WriteReply(control, 0x01, nil)
					return
				}
			}
			c.manager.invalidate(h3Conn)
		}
		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err != nil {
		_ = socks5.WriteReply(control, 0x01, nil)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Printf("V2 UDP association rejected: status=%d", response.StatusCode)
		_ = socks5.WriteReply(control, 0x01, nil)
		return
	}
	if err := socks5.WriteReply(control, 0x00, udpConn.LocalAddr()); err != nil {
		return
	}
	log.Printf("V2 UDP association established")
	_ = control.SetDeadline(time.Time{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		cancel()
		_ = udpConn.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}()

	var peerMu sync.RWMutex
	var peer *net.UDPAddr
	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		var replay frame.ReplayWindow
		var decoder frame.DatagramCache
		socksPacketBuffer := make([]byte, 64<<10)
		for {
			packet, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("V2 UDP receive stopped: %v", err)
				}
				return
			}
			sequence, address, payload, err := decoder.Decode(packet)
			if err != nil || !replay.Accept(sequence) {
				continue
			}
			socksPacket, err := socks5.BuildUDPPacketInto(socksPacketBuffer, address, payload)
			if err != nil {
				continue
			}
			peerMu.RLock()
			clientAddress := peer
			peerMu.RUnlock()
			if clientAddress != nil {
				_, _ = udpConn.WriteToUDP(socksPacket, clientAddress)
			}
		}
	}()

	buffer := make([]byte, 64<<10)
	var addressCache socks5.UDPCache
	datagramBuffer := make([]byte, frame.MaxDatagramSize)
	oversizeLogged := false
	var sequence atomic.Uint64
	for {
		n, clientAddress, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			break
		}
		peerMu.Lock()
		if peer == nil {
			peer = clientAddress
		}
		acceptedPeer := peer.IP.Equal(clientAddress.IP) && peer.Port == clientAddress.Port
		peerMu.Unlock()
		if !acceptedPeer {
			continue
		}
		address, payload, err := addressCache.Parse(buffer[:n])
		if err != nil {
			continue
		}
		packet, err := frame.EncodeDatagramInto(datagramBuffer, sequence.Add(1), address, payload)
		if err != nil {
			continue
		}
		if err := stream.SendDatagram(packet); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				if !oversizeLogged {
					log.Printf("V2 UDP datagram dropped: path datagram limit=%d", tooLarge.MaxDatagramPayloadSize)
					oversizeLogged = true
				}
				continue
			}
			log.Printf("V2 UDP send stopped: %v", err)
			break
		}
	}
	cancel()
	stream.CancelRead(0)
	stream.CancelWrite(0)
	<-receiveDone
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "443"
	}
	return port
}

func loadPath(value, pathFile string) (string, error) {
	if value == "" && pathFile != "" {
		raw, err := os.ReadFile(pathFile)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(raw))
	}
	if !strings.HasPrefix(value, "/") || len(value) < 16 || strings.ContainsAny(value, "?#") {
		return "", errors.New("invalid private path")
	}
	return value, nil
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lmsgprefix)
	log.SetPrefix("myxray-v2-client: ")
}

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
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/ipv4"

	"myxray/internal/auth"
	"myxray/internal/frame"
	"myxray/internal/quicconfig"
	"myxray/internal/sessioncache"
	"myxray/internal/socks5"
)

const (
	headerTarget      = "X-Session-Target"
	headerTimestamp   = "X-Session-Time"
	headerNonce       = "X-Session-Nonce"
	headerSignature   = "X-Session-Auth"
	headerSessionOK   = "X-Session-OK"
	headerFraming     = "X-Session-Framing"
	headerMode        = "X-Session-Mode"
	modeTCPv2         = "tcp-v2"
	modeUDPv2         = "udp-v2"
	modeTCPH2Framed   = "tcp-h2-framed"
	udpAuthName       = "udp-association"
	udpLocalBatchSize = 32
	tcpTransportAuto    = "auto"
	tcpTransportH2      = "h2"
	tcpTransportH3      = "h3"
	defaultTCPTransport = tcpTransportH2

	socksNegotiationTimeout = 15 * time.Second
	autoH2ConnectTimeout    = 4 * time.Second
	carrierConnectTimeout   = 15 * time.Second
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
	// TCP and UDP must not share congestion-control state.
	currentTCP *connection
	currentUDP *connection
}

type proxyClient struct {
	manager            *manager
	h2                 *h2Client
	tcpTransport       string
	localUDPReadBuffer int
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
	cpuProfile := flag.String("cpu-profile", "", "optional CPU profile output file")
	tcpTransport := flag.String("tcp-transport", defaultTCPTransport, "TCP carrier: h2 (default), auto or h3")
	quicInitialPacketSize := flag.Uint("quic-initial-packet-size", quicconfig.DefaultInitialPacketSize, "QUIC initial packet size (1200-1452)")
	localUDPReadBuffer := flag.Int("udp-local-read-buffer", 4<<20, "local SOCKS UDP receive buffer in bytes")
	flag.Parse()
	stopCPUProfile, err := startCPUProfile(*cpuProfile)
	if err != nil {
		log.Fatalf("start CPU profile: %v", err)
	}
	defer stopCPUProfile()
	if !validTCPTransport(*tcpTransport) {
		log.Fatal("tcp-transport must be auto, h2 or h3")
	}
	if *quicInitialPacketSize < quicconfig.MinInitialPacketSize || *quicInitialPacketSize > quicconfig.MaxInitialPacketSize {
		log.Fatal("quic-initial-packet-size must be between 1200 and 1452")
	}
	if *localUDPReadBuffer < 64<<10 || *localUDPReadBuffer > 16<<20 {
		log.Fatal("udp-local-read-buffer must be between 65536 and 16777216")
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
	var h2 *h2Client
	if *tcpTransport != tcpTransportH3 {
		h2, err = newH2Client(*serverAddress, *serverName, path, psk)
		if err != nil {
			log.Fatalf("configure HTTP/2 TCP carrier: %v", err)
		}
		defer h2.CloseIdleConnections()
		prewarmCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := h2.Prewarm(prewarmCtx); err != nil {
			log.Printf("HTTP/2 prewarm failed; first TCP stream will retry")
		}
		cancel()
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	client := &proxyClient{
		manager:            mgr,
		h2:                 h2,
		tcpTransport:       *tcpTransport,
		localUDPReadBuffer: *localUDPReadBuffer,
	}
	log.Printf("V2 SOCKS5 TCP/UDP listener started on %s; tcp_transport=%s ticket_cached=%v", *listen, *tcpTransport, cache.HasEntries())

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

func startCPUProfile(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	profile, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(profile); err != nil {
		_ = profile.Close()
		return nil, err
	}
	return func() {
		pprof.StopCPUProfile()
		_ = profile.Close()
	}, nil
}

func (m *manager) ensureConnection(ctx context.Context, current **connection) (*connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if *current != nil && (*current).quic.Context().Err() == nil {
		return *current, nil
	}
	quicConn, err := quic.DialAddrEarly(ctx, m.server, m.tlsConfig.Clone(), m.quicConfig.Clone())
	if err != nil {
		return nil, err
	}
	*current = &connection{quic: quicConn, h3: m.transport.NewClientConn(quicConn)}
	return *current, nil
}

func (m *manager) ensureTCPConnection(ctx context.Context) (*connection, error) {
	return m.ensureConnection(ctx, &m.currentTCP)
}

func (m *manager) ensureUDPConnection(ctx context.Context) (*connection, error) {
	return m.ensureConnection(ctx, &m.currentUDP)
}

func (m *manager) invalidate(value *connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	invalidated := false
	if m.currentTCP == value {
		m.currentTCP = nil
		invalidated = true
	}
	if m.currentUDP == value {
		m.currentUDP = nil
		invalidated = true
	}
	if invalidated {
		_ = value.quic.CloseWithError(0, "reconnect")
	}
}

func (m *manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentTCP != nil {
		_ = m.currentTCP.quic.CloseWithError(0, "shutdown")
		m.currentTCP = nil
	}
	if m.currentUDP != nil {
		_ = m.currentUDP.quic.CloseWithError(0, "shutdown")
		m.currentUDP = nil
	}
	_ = m.transport.Close()
}

func (m *manager) provision(ctx context.Context) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := m.ensureTCPConnection(ctx)
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
		conn, err := m.ensureTCPConnection(ctx)
		if err != nil {
			return nil, nil, err
		}
		stream, err := conn.h3.OpenRequestStream(ctx)
		if err == nil {
			if deadline, ok := ctx.Deadline(); ok {
				err = stream.SetDeadline(deadline)
			}
		}
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
		if stream != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
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
	conn, err := m.ensureUDPConnection(ctx)
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
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return nil, conn, err
		}
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
	_ = conn.SetDeadline(time.Now().Add(socksNegotiationTimeout))
	request, err := socks5.Negotiate(conn)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	switch request.Command {
	case socks5.CommandConnect:
		c.handleTCP(conn, request)
	case socks5.CommandUDPAssociate:
		c.handleUDP(conn)
	}
}

func (c *proxyClient) handleTCPH3(local net.Conn, request socks5.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), carrierConnectTimeout)
	defer cancel()
	connectDeadline, _ := ctx.Deadline()
	stream, h3Conn, err := c.manager.openTCP(ctx, request.Target)
	if err != nil {
		_ = socks5.WriteReply(local, 0x01, nil)
		return
	}
	uploadDone := make(chan error, 1)
	go func() {
		uploadErr := frame.CopyAsDataFramesAndClose(stream, request.Reader)
		if uploadErr != nil {
			stream.CancelWrite(0)
		} else {
			_ = stream.Close()
		}
		uploadDone <- uploadErr
	}()
	response, err := stream.ReadResponse()
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		c.manager.invalidate(h3Conn)
		_ = socks5.WriteReply(local, 0x01, nil)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get(headerSessionOK) != "1" {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = socks5.WriteReply(local, 0x01, nil)
		return
	}
	if err := readOpenAck(stream); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		c.manager.invalidate(h3Conn)
		_ = socks5.WriteReply(local, 0x01, nil)
		return
	}
	if time.Now().After(connectDeadline) {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = socks5.WriteReply(local, 0x01, nil)
		return
	}
	_ = stream.SetDeadline(time.Time{})
	if err := socks5.WriteReply(local, 0x00, nil); err != nil {
		return
	}
	state := h3Conn.quic.ConnectionState()
	log.Printf("V2 TCP stream established: used_0rtt=%v early_accepted=%v", state.Used0RTT, response.Header.Get("X-Session-Early") == "1")
	receiveErr := copyDataFramesToLocal(stream, local)
	if receiveErr != nil {
		if !errors.Is(receiveErr, io.EOF) {
			log.Printf("V2 TCP receive failed")
		}
		stream.CancelWrite(0)
		_ = local.Close()
		select {
		case <-uploadDone:
		case <-time.After(time.Second):
		}
		return
	}
	select {
	case <-uploadDone:
	case <-h3Conn.quic.Context().Done():
		_ = local.Close()
		stream.CancelWrite(0)
		<-uploadDone
	}
	_ = local.Close()
}

func copyDataFramesToLocal(stream io.Reader, local net.Conn) error {
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

func readOpenAck(stream io.Reader) error {
	header, err := frame.ReadHeader(stream)
	if err != nil {
		return err
	}
	if header.Type != frame.TypeOpenAck || header.Flags != 0 || header.Length != 0 {
		return errors.New("missing OPEN_ACK")
	}
	return nil
}

func (c *proxyClient) handleUDP(control net.Conn) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = socks5.WriteReply(control, 0x01, nil)
		return
	}
	defer udpConn.Close()
	if err := udpConn.SetReadBuffer(c.localUDPReadBuffer); err != nil {
		log.Printf("set local UDP receive buffer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connectCtx, connectCancel := context.WithTimeout(ctx, carrierConnectTimeout)
	defer connectCancel()
	var stream *http3.RequestStream
	var h3Conn *connection
	var response *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		stream, h3Conn, err = c.manager.openUDP(connectCtx)
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
	if response.StatusCode != http.StatusOK || response.Header.Get(headerSessionOK) != "1" {
		log.Printf("V2 UDP association rejected: status=%d", response.StatusCode)
		_ = socks5.WriteReply(control, 0x01, nil)
		return
	}
	if err := socks5.WriteReply(control, 0x00, udpConn.LocalAddr()); err != nil {
		return
	}
	_ = stream.SetDeadline(time.Time{})
	connectCancel()
	log.Printf("V2 UDP association established")
	_ = control.SetDeadline(time.Time{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		cancel()
		_ = udpConn.Close()
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}()

	var peer atomic.Pointer[net.UDPAddr]
	packetConn := ipv4.NewPacketConn(udpConn)
	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		var replay frame.ReplayWindow
		var decoder frame.DatagramCache
		var socksBuilder socks5.UDPBuilderCache
		var packetBuffer [udpLocalBatchSize][]byte
		var socksPacketBuffers [udpLocalBatchSize][]byte
		var messages [udpLocalBatchSize]ipv4.Message
		for i := range messages {
			socksPacketBuffers[i] = make([]byte, frame.MaxDatagramSize)
			messages[i].Buffers = make([][]byte, 1)
		}
		for {
			packets, err := receiveClientDatagramBatch(ctx, stream, packetBuffer[:])
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("V2 UDP receive stopped: %v", err)
				}
				return
			}
			clientAddress := peer.Load()
			messageCount := 0
			if clientAddress != nil {
				for _, packet := range packets {
					sequence, address, payload, err := decoder.Decode(packet)
					if err != nil || !replay.Accept(sequence) {
						continue
					}
					socksPacket, err := socksBuilder.BuildInto(socksPacketBuffers[messageCount], address, payload)
					if err != nil {
						continue
					}
					messages[messageCount].Buffers[0] = socksPacket
					messages[messageCount].Addr = clientAddress
					messageCount++
				}
			}
			written := 0
			if messageCount > 1 {
				written, _ = packetConn.WriteBatch(messages[:messageCount], 0)
				written = max(0, min(written, messageCount))
			}
			for i := written; i < messageCount; i++ {
				_, _ = udpConn.WriteToUDP(messages[i].Buffers[0], clientAddress)
			}
			for i := range packets {
				packetBuffer[i] = nil
			}
			for i := range messageCount {
				messages[i].Buffers[0] = nil
				messages[i].Addr = nil
			}
		}
	}()

	var messages [udpLocalBatchSize]ipv4.Message
	var buffers [udpLocalBatchSize][]byte
	var datagramBuffers [udpLocalBatchSize][]byte
	var datagrams [udpLocalBatchSize][]byte
	for i := range messages {
		buffers[i] = make([]byte, frame.MaxDatagramSize)
		messages[i].Buffers = [][]byte{buffers[i]}
		datagramBuffers[i] = make([]byte, frame.MaxDatagramSize)
	}
	var addressCache socks5.UDPCache
	oversizeLogged := false
	var sequence atomic.Uint64
	for {
		count, err := packetConn.ReadBatch(messages[:], 0)
		if err != nil {
			break
		}
		datagramCount := 0
		for i := range count {
			clientAddress, ok := messages[i].Addr.(*net.UDPAddr)
			if !ok || messages[i].N < 1 {
				continue
			}
			knownPeer := peer.Load()
			if knownPeer == nil {
				candidate := &net.UDPAddr{IP: append(net.IP(nil), clientAddress.IP...), Port: clientAddress.Port, Zone: clientAddress.Zone}
				if peer.CompareAndSwap(nil, candidate) {
					knownPeer = candidate
				} else {
					knownPeer = peer.Load()
				}
			}
			acceptedPeer := knownPeer != nil && knownPeer.IP.Equal(clientAddress.IP) && knownPeer.Port == clientAddress.Port && knownPeer.Zone == clientAddress.Zone
			if !acceptedPeer {
				continue
			}
			address, payload, err := addressCache.Parse(messages[i].Buffers[0][:messages[i].N])
			if err != nil {
				continue
			}
			packet, err := frame.EncodeDatagramInto(datagramBuffers[datagramCount], sequence.Add(1), address, payload)
			if err != nil {
				continue
			}
			datagrams[datagramCount] = packet
			datagramCount++
		}
		if err := sendDatagramBatch(stream, datagrams[:datagramCount], &oversizeLogged); err != nil {
			log.Printf("V2 UDP send stopped: %v", err)
			cancel()
			stream.CancelRead(0)
			stream.CancelWrite(0)
			<-receiveDone
			return
		}
		for i := range datagramCount {
			datagrams[i] = nil
		}
	}
	cancel()
	stream.CancelRead(0)
	stream.CancelWrite(0)
	<-receiveDone
}

type datagramBatchSender interface {
	SendDatagrams([][]byte) error
}

type datagramBatchReceiver interface {
	ReceiveDatagramsInto(context.Context, [][]byte) (int, error)
}

func receiveClientDatagramBatch(ctx context.Context, stream *http3.RequestStream, buffer [][]byte) ([][]byte, error) {
	if receiver, ok := any(stream).(datagramBatchReceiver); ok {
		count, err := receiver.ReceiveDatagramsInto(ctx, buffer)
		if count < 0 || count > len(buffer) {
			return nil, errors.New("invalid HTTP Datagram batch size")
		}
		return buffer[:count], err
	}
	packet, err := stream.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	buffer[0] = packet
	return buffer[:1], nil
}

func sendDatagramBatch(stream *http3.RequestStream, datagrams [][]byte, oversizeLogged *bool) error {
	if len(datagrams) == 0 {
		return nil
	}
	if sender, ok := any(stream).(datagramBatchSender); ok {
		err := sender.SendDatagrams(datagrams)
		if err == nil {
			return nil
		}
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			return err
		}
	}
	for _, datagram := range datagrams {
		if err := stream.SendDatagram(datagram); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				if !*oversizeLogged {
					log.Printf("V2 UDP datagram dropped: path datagram limit=%d", tooLarge.MaxDatagramPayloadSize)
					*oversizeLogged = true
				}
				continue
			}
			return err
		}
	}
	return nil
}

func portOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "443"
	}
	return port
}

func validTCPTransport(value string) bool {
	return value == tcpTransportAuto || value == tcpTransportH2 || value == tcpTransportH3
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

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"myxray/internal/auth"
)

const (
	headerTarget    = "X-Session-Target"
	headerTimestamp = "X-Session-Time"
	headerNonce     = "X-Session-Nonce"
	headerSignature = "X-Session-Auth"
)

type client struct {
	psk        []byte
	path       string
	requestURL string
	httpClient *http.Client
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2080", "local SOCKS5 listen address")
	serverAddress := flag.String("server", "23.145.248.44:11322", "server TCP address")
	serverName := flag.String("server-name", "probe.chitanda.org", "TLS server name")
	pskFile := flag.String("psk-file", "", "hex or base64url PSK file")
	privatePath := flag.String("path", "", "private HTTP path")
	pathFile := flag.String("path-file", "", "file containing the private HTTP path")
	flag.Parse()

	path, err := loadPath(*privatePath, *pathFile)
	if *pskFile == "" || err != nil {
		log.Fatal("psk-file and private path are required")
	}
	psk, err := auth.LoadPSK(*pskFile)
	if err != nil {
		log.Fatalf("load PSK: %v", err)
	}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     3 * time.Minute,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, ServerName: *serverName},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, network, *serverAddress)
		},
	}
	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		log.Fatalf("configure HTTP/2 transport: %v", err)
	}
	h2Transport.ReadIdleTimeout = 45 * time.Second
	h2Transport.PingTimeout = 15 * time.Second
	c := &client{
		psk:        psk,
		path:       path,
		requestURL: "https://" + net.JoinHostPort(*serverName, portOf(*serverAddress)) + path,
		httpClient: &http.Client{Transport: transport},
	}
	c.prewarm(*serverName, portOf(*serverAddress))

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Printf("SOCKS5 listener started on %s", *listen)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = listener.Close()
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
		go c.handleSOCKS(conn)
	}
}

func (c *client) handleSOCKS(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, buffered, err := negotiateSOCKS(conn)
	if err != nil {
		return
	}

	response, upload, err := c.openStream(target)
	if err != nil {
		log.Printf("open stream failed: %v", err)
		writeSOCKSReply(conn, 0x01)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Printf("open stream rejected with HTTP status %d", response.StatusCode)
		writeSOCKSReply(conn, 0x05)
		return
	}
	if err := writeSOCKSReply(conn, 0x00); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, _ = io.Copy(upload, buffered)
		_ = upload.Close()
	}()
	_, _ = io.Copy(conn, response.Body)
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = conn.Close()
	_ = upload.Close()
	<-uploadDone
}

func (c *client) openStream(target string) (*http.Response, *io.PipeWriter, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		response, writer, err := c.openStreamOnce(target)
		if err == nil {
			return response, writer, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (c *client) openStreamOnce(target string) (*http.Response, *io.PipeWriter, error) {
	reader, writer := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, c.requestURL, reader)
	if err != nil {
		return nil, nil, err
	}
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(headerTarget, target)
	request.Header.Set(headerTimestamp, timestamp)
	request.Header.Set(headerNonce, nonce)
	request.Header.Set(headerSignature, auth.Signature(c.psk, "tcp-v2", request.Method, c.path, target, timestamp, nonce))

	response, err := c.httpClient.Do(request)
	if err != nil {
		_ = writer.CloseWithError(err)
		return nil, nil, err
	}
	return response, writer, nil
}

func (c *client) prewarm(serverName, port string) {
	root := "https://" + net.JoinHostPort(serverName, port) + "/"
	request, _ := http.NewRequest(http.MethodHead, root, nil)
	response, err := c.httpClient.Do(request)
	if err != nil {
		log.Printf("prewarm failed: %v", err)
		return
	}
	_ = response.Body.Close()
	log.Printf("TLS/H2 connection prewarmed")
}

func negotiateSOCKS(conn net.Conn) (string, *bufio.Reader, error) {
	reader := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 0x05 {
		return "", nil, errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return "", nil, err
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0x00
	}
	if !noAuth {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return "", nil, errors.New("no supported authentication method")
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", nil, err
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil || request[0] != 0x05 || request[1] != 0x01 {
		return "", nil, errors.New("unsupported SOCKS request")
	}
	var host string
	switch request[3] {
	case 0x01:
		value := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", nil, err
		}
		host = net.IP(value).String()
	case 0x03:
		length, err := reader.ReadByte()
		if err != nil {
			return "", nil, err
		}
		value := make([]byte, int(length))
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", nil, err
		}
		host = string(value)
	case 0x04:
		value := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, value); err != nil {
			return "", nil, err
		}
		host = net.IP(value).String()
	default:
		return "", nil, errors.New("unsupported address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), reader, nil
}

func writeSOCKSReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
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
	log.SetPrefix("myxray-client: ")
}

package main

import (
	"flag"
	"log"

	"myxray/pkg/server"
)

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
	udpTargetBuffer := flag.Int("udp-target-buffer", 8<<20, "UDP target socket buffer in bytes")
	quicInitialPacketSize := flag.Uint("quic-initial-packet-size", 1452, "QUIC initial packet size (1200-1452)")
	strictSNI := flag.String("strict-sni", "", "Optional: enforce Strict SNI matching on ClientHello")
	allowPrivateTargets := flag.Bool("allow-private-targets", false, "Allow dialing private/loopback targets (for testing)")

	flag.Parse()

	cfg := &server.Config{
		CertFile:              *certFile,
		KeyFile:               *keyFile,
		PSKFile:               *pskFile,
		PrivatePath:           *privatePath,
		PathFile:              *pathFile,
		FallbackURL:           *fallbackURL,
		FallbackServerName:    *fallbackServerName,
		ReplayFile:            *replayFile,
		TicketKeyFile:         *ticketKeyFile,
		UDPTargetBuffer:       *udpTargetBuffer,
		QuicInitialPacketSize: uint16(*quicInitialPacketSize),
		StrictSNI:             *strictSNI,
		AllowPrivateTargets:   *allowPrivateTargets,
	}

	log.Printf("Starting myxray-server componentized version...")
	if err := server.Run(cfg, *listen, *adminListen, *quicListen); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lmsgprefix)
	log.SetPrefix("myxray-server: ")
}

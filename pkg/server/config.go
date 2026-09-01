package server

import (
	"fmt"
	"os"
	"strings"
	"time"

	"myxray/internal/auth"
)

// Config represents the server configuration parameters.
type Config struct {
	CertFile              string
	KeyFile               string
	PSKFile               string
	PrivatePath           string
	PathFile              string
	FallbackURL           string
	FallbackServerName    string
	ReplayFile            string
	TicketKeyFile         string
	UDPTargetBuffer       int
	QuicInitialPacketSize uint16
	StrictSNI             string // The allowed SNI for Strict SNI checking
	AllowPrivateTargets   bool   // Allow loopback and private IP targets (for local benchmarks)
}

// Init loads configurations and initialized components
func (c *Config) Init() (string, []byte, *auth.ReplayCache, error) {
	path, err := loadPath(c.PrivatePath, c.PathFile)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid path: %v", err)
	}
	if c.PSKFile == "" {
		return "", nil, nil, fmt.Errorf("psk-file is required")
	}
	if (c.CertFile == "" && c.KeyFile != "") || (c.CertFile != "" && c.KeyFile == "") {
		return "", nil, nil, fmt.Errorf("both cert and key must be provided together, or both omitted for plain-h1 mode")
	}

	psk, err := auth.LoadPSK(c.PSKFile)
	if err != nil {
		return "", nil, nil, fmt.Errorf("load PSK: %v", err)
	}

	replays, err := auth.OpenReplayCache(c.ReplayFile, time.Now())
	if err != nil {
		return "", nil, nil, fmt.Errorf("open replay cache: %v", err)
	}

	return path, psk, replays, nil
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
		return "", fmt.Errorf("private path must start with '/' and be at least 16 chars")
	}
	return value, nil
}

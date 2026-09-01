package chitanda

// InboundConfig specifies configuration for Chitanda inbound proxy
type InboundConfig struct {
	PSK          string `json:"psk"`
	Path         string `json:"path"`
	Fallback     string `json:"fallback,omitempty"`
	CertFile     string `json:"certFile,omitempty"`
	KeyFile      string `json:"keyFile,omitempty"`
	ReplayFile   string `json:"replayFile,omitempty"`
	StrictMode   bool   `json:"strictMode,omitempty"`
	StrictSNI    string `json:"strictSNI,omitempty"`
}

// OutboundConfig specifies configuration for Chitanda outbound proxy
type OutboundConfig struct {
	Server       string `json:"server"`
	ServerName   string `json:"serverName,omitempty"`
	PSK          string `json:"psk"`
	Path         string `json:"path"`
	Transport    string `json:"transport,omitempty"` // "h2", "h3", "auto", "h1"
	PoolSize     int    `json:"poolSize,omitempty"`
}

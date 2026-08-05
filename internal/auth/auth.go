package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxClockSkew = 90 * time.Second

type ReplayCache struct {
	mu      sync.Mutex
	expires map[string]time.Time
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{expires: make(map[string]time.Time)}
}

func (c *ReplayCache) Accept(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, expiry := range c.expires {
		if !expiry.After(now) {
			delete(c.expires, key)
		}
	}
	if _, exists := c.expires[nonce]; exists {
		return false
	}
	c.expires[nonce] = now.Add(2 * MaxClockSkew)
	return true
}

func LoadPSK(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(string(raw))
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	return nil, errors.New("PSK must be at least 32 bytes encoded as hex or base64url")
}

func Signature(psk []byte, method, path, target, timestamp, nonce string) string {
	mac := hmac.New(sha256.New, psk)
	fmt.Fprintf(mac, "%s\n%s\n%s\n%s\n%s", method, path, target, timestamp, nonce)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func Verify(psk []byte, method, path, target, timestamp, nonce, signature string, now time.Time) bool {
	unixSeconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || nonce == "" || signature == "" {
		return false
	}
	requestTime := time.Unix(unixSeconds, 0)
	if requestTime.Before(now.Add(-MaxClockSkew)) || requestTime.After(now.Add(MaxClockSkew)) {
		return false
	}
	expected := Signature(psk, method, path, target, timestamp, nonce)
	return hmac.Equal([]byte(expected), []byte(signature))
}

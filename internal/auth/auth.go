package auth

import (
	"bufio"
	"container/heap"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxClockSkew = 90 * time.Second

const replayCompactAfter = 10_000

type ReplayCache struct {
	mu          sync.Mutex
	expires     map[string]time.Time
	expiryQueue replayExpiryHeap
	file        *os.File
	path        string
	writesSince int
}

type replayExpiry struct {
	nonce  string
	expiry time.Time
}

type replayExpiryHeap []replayExpiry

func (h replayExpiryHeap) Len() int           { return len(h) }
func (h replayExpiryHeap) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h replayExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *replayExpiryHeap) Push(value any) {
	*h = append(*h, value.(replayExpiry))
}

func (h *replayExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	*h = old[:last]
	return value
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{expires: make(map[string]time.Time)}
}

func OpenReplayCache(path string, now time.Time) (*ReplayCache, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("replay cache path is required")
	}
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if created {
		directory, openErr := os.Open(filepath.Dir(path))
		if openErr != nil {
			_ = file.Close()
			return nil, openErr
		}
		syncErr := directory.Sync()
		_ = directory.Close()
		if syncErr != nil {
			_ = file.Close()
			return nil, syncErr
		}
	}
	cache := &ReplayCache{expires: make(map[string]time.Time), file: file, path: path}
	if err := cache.load(now); err != nil {
		_ = file.Close()
		return nil, err
	}
	return cache, nil
}

func (c *ReplayCache) load(now time.Time) error {
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(c.file)
	for scanner.Scan() {
		expiryText, encodedNonce, ok := strings.Cut(scanner.Text(), "\t")
		expiryUnix, err := strconv.ParseInt(expiryText, 10, 64)
		if !ok || err != nil {
			return errors.New("invalid replay cache record")
		}
		nonceBytes, err := base64.RawURLEncoding.DecodeString(encodedNonce)
		if err != nil || len(nonceBytes) == 0 {
			return errors.New("invalid replay cache nonce")
		}
		expiry := time.Unix(expiryUnix, 0)
		if expiry.After(now) {
			nonce := string(nonceBytes)
			c.expires[nonce] = expiry
			heap.Push(&c.expiryQueue, replayExpiry{nonce: nonce, expiry: expiry})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	_, err := c.file.Seek(0, io.SeekEnd)
	return err
}

func (c *ReplayCache) Accept(nonce string, now time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for c.expiryQueue.Len() > 0 && !c.expiryQueue[0].expiry.After(now) {
		expired := heap.Pop(&c.expiryQueue).(replayExpiry)
		if current, exists := c.expires[expired.nonce]; exists && current.Equal(expired.expiry) {
			delete(c.expires, expired.nonce)
		}
	}
	if _, exists := c.expires[nonce]; exists {
		return false, nil
	}
	if c.file != nil {
		if c.writesSince >= replayCompactAfter {
			if err := c.compact(); err != nil {
				return false, err
			}
		}
		expiry := now.Add(2 * MaxClockSkew)
		record := strconv.FormatInt(expiry.Unix(), 10) + "\t" + base64.RawURLEncoding.EncodeToString([]byte(nonce)) + "\n"
		if _, err := io.WriteString(c.file, record); err != nil {
			return false, err
		}
		if err := c.file.Sync(); err != nil {
			return false, err
		}
		c.writesSince++
	}
	expiry := now.Add(2 * MaxClockSkew)
	c.expires[nonce] = expiry
	heap.Push(&c.expiryQueue, replayExpiry{nonce: nonce, expiry: expiry})
	return true, nil
}

func (c *ReplayCache) compact() error {
	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".replay-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	for nonce, expiry := range c.expires {
		record := strconv.FormatInt(expiry.Unix(), 10) + "\t" + base64.RawURLEncoding.EncodeToString([]byte(nonce)) + "\n"
		if _, err := io.WriteString(temporary, record); err != nil {
			cleanup()
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return err
	}
	if err := c.file.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, c.path); err != nil {
		c.file, _ = os.OpenFile(c.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
		_ = os.Remove(temporaryPath)
		return err
	}
	c.file, err = os.OpenFile(c.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(c.path))
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	if err != nil {
		return err
	}
	c.writesSince = 0
	return nil
}

func (c *ReplayCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
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

package sessioncache

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type diskEntry struct {
	Ticket string `json:"ticket"`
	State  string `json:"state"`
}

type Cache struct {
	mu      sync.Mutex
	path    string
	entries map[string]diskEntry
	updated chan struct{}
	lastErr error
}

func Open(path string) (*Cache, error) {
	if path == "" {
		return nil, errors.New("session cache path is required")
	}
	cache := &Cache{path: path, entries: make(map[string]diskEntry), updated: make(chan struct{}, 1)}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cache, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cache.entries); err != nil {
			return nil, err
		}
	}
	return cache, nil
}

func (c *Cache) Get(key string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	ticket, ticketErr := base64.RawStdEncoding.DecodeString(entry.Ticket)
	stateBytes, stateErr := base64.RawStdEncoding.DecodeString(entry.State)
	if ticketErr != nil || stateErr != nil {
		delete(c.entries, key)
		return nil, false
	}
	state, err := tls.ParseSessionState(stateBytes)
	if err != nil {
		delete(c.entries, key)
		return nil, false
	}
	clientState, err := tls.NewResumptionState(ticket, state)
	if err != nil {
		delete(c.entries, key)
		return nil, false
	}
	return clientState, true
}

func (c *Cache) Put(key string, state *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if state == nil {
		delete(c.entries, key)
		c.lastErr = c.persistLocked()
		return
	}
	ticket, session, err := state.ResumptionState()
	if err != nil {
		c.lastErr = err
		return
	}
	serialized, err := session.Bytes()
	if err != nil {
		c.lastErr = err
		return
	}
	c.entries[key] = diskEntry{
		Ticket: base64.RawStdEncoding.EncodeToString(ticket),
		State:  base64.RawStdEncoding.EncodeToString(serialized),
	}
	c.lastErr = c.persistLocked()
	if c.lastErr == nil {
		select {
		case c.updated <- struct{}{}:
		default:
		}
	}
}

func (c *Cache) HasEntries() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries) > 0
}

func (c *Cache) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]diskEntry)
	c.lastErr = c.persistLocked()
	return c.lastErr
}

func (c *Cache) WaitForUpdate(ctx context.Context) error {
	select {
	case <-c.updated:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Cache) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(c.entries)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(c.path), ".sessions-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, c.path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(c.path))
}

func syncDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	_ = directory.Close()
	return syncErr
}

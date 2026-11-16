// Package state keeps the agent's enrollment on disk: the server it belongs
// to, its device id and its private key.
package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Config is the agent's enrollment, stored as JSON. It holds no secret.
type Config struct {
	Server     string    `json:"server"`
	CAFile     string    `json:"caFile,omitempty"`
	DeviceID   string    `json:"deviceId"`
	EnrolledAt time.Time `json:"enrolledAt"`
	// MeshAgentMode is how MeshAgent runs: "systemd" or "child".
	MeshAgentMode string `json:"meshAgentMode"`
	// JobKey is the server's job-signing public key, pinned the first time
	// the server sends it (ADR-0017). Jobs signed by any other key are
	// refused.
	JobKey string `json:"jobKey,omitempty"`
}

// Store reads and writes the agent's files under one directory.
type Store struct {
	Dir string
}

const (
	configFile = "agent.json"
	keyFile    = "device.key"
	statusFile = "status.json"
)

// ErrNotEnrolled means the agent has no enrollment yet.
var ErrNotEnrolled = errors.New("the agent is not enrolled")

// Load returns the enrollment and private key.
func (s Store) Load() (*Config, ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, configFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", configFile, err)
	}
	if c.Server == "" || c.DeviceID == "" {
		return nil, nil, fmt.Errorf("%s is incomplete", configFile)
	}
	key, err := s.loadKey()
	if err != nil {
		return nil, nil, err
	}
	return &c, key, nil
}

func (s Store) loadKey() (ed25519.PrivateKey, error) {
	path := filepath.Join(s.Dir, keyFile)
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be readable by its owner only (mode %v)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // inside the agent's state directory
	if err != nil {
		return nil, fmt.Errorf("reading the device key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "EASYRMM DEVICE KEY" || len(blk.Bytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a device key", path)
	}
	return ed25519.NewKeyFromSeed(blk.Bytes), nil
}

// NewKey generates a device key pair. Nothing is written yet.
func NewKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// Save writes the enrollment and key. The key file is readable by its
// owner only and written before the configuration, so a configuration
// never points at a missing key.
func (s Store) Save(c *Config, key ed25519.PrivateKey) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil { //nolint:gosec // a directory, owner only
		return err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EASYRMM DEVICE KEY", Bytes: key.Seed()})
	if err := writeFile(filepath.Join(s.Dir, keyFile), pemKey, 0o600); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.Dir, configFile), append(b, '\n'), 0o600)
}

// SaveConfig rewrites the configuration of an enrolled agent.
func (s Store) SaveConfig(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.Dir, configFile), append(b, '\n'), 0o600)
}

// JobsDir holds the job journal and the runs' working directories.
func (s Store) JobsDir() string { return filepath.Join(s.Dir, "jobs") }

// Status is what the running agent last observed, for `easyrmm-agent status`.
type Status struct {
	LastHeartbeat time.Time `json:"lastHeartbeat,omitzero"`
	LastError     string    `json:"lastError,omitempty"`
	LastErrorAt   time.Time `json:"lastErrorAt,omitzero"`
	MeshAgent     string    `json:"meshAgent,omitempty"` // "installed", "not available", ...
	MeshNodeID    string    `json:"meshNodeId,omitempty"`
}

// SaveStatus records the running agent's status.
func (s Store) SaveStatus(st Status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.Dir, statusFile), append(b, '\n'), 0o600)
}

// LoadStatus reads the last recorded status.
func (s Store) LoadStatus() (Status, error) {
	var st Status
	b, err := os.ReadFile(filepath.Join(s.Dir, statusFile))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// Remove deletes the agent's files.
func (s Store) Remove() error { return os.RemoveAll(s.Dir) }

// writeFile replaces path atomically.
func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

package workload

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// maxJWKSBytes bounds a JWKS document read from disk or network.
const maxJWKSBytes = 64 * 1024

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

// ParseJWKS extracts the Ed25519 (OKP/Ed25519) keys from a JWKS document,
// keyed by kid. Keys of other types are ignored; a document with no usable
// key is an error so a misconfigured key source fails loudly.
func ParseJWKS(data []byte) (map[string]ed25519.PublicKey, error) {
	if len(data) > maxJWKSBytes {
		return nil, fmt.Errorf("jwks exceeds %d bytes", maxJWKSBytes)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("jwks json: %w", err)
	}
	out := make(map[string]ed25519.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwks key %q: invalid Ed25519 x", k.Kid)
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("jwks: duplicate kid %q", k.Kid)
		}
		out[k.Kid] = ed25519.PublicKey(raw)
	}
	if len(out) == 0 {
		return nil, errNoKeys
	}
	return out, nil
}

// StaticKeySet is an immutable in-memory key set (JWKS file or inline).
type StaticKeySet struct {
	keys map[string]ed25519.PublicKey
}

// NewStaticKeySet wraps parsed keys.
func NewStaticKeySet(keys map[string]ed25519.PublicKey) *StaticKeySet {
	cp := make(map[string]ed25519.PublicKey, len(keys))
	for k, v := range keys {
		cp[k] = v
	}
	return &StaticKeySet{keys: cp}
}

// LoadJWKSFile reads a JWKS document from disk.
func LoadJWKSFile(path string) (*StaticKeySet, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured key material path
	if err != nil {
		return nil, fmt.Errorf("reading jwks file: %w", err)
	}
	keys, err := ParseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("jwks file %s: %w", path, err)
	}
	return NewStaticKeySet(keys), nil
}

// Key implements KeySet.
func (s *StaticKeySet) Key(kid string) (ed25519.PublicKey, bool, error) {
	if s == nil {
		return nil, false, errNoKeys
	}
	k, ok := s.keys[kid]
	return k, ok, nil
}

// RemoteKeySet fetches a JWKS document over HTTPS and caches it. An
// unknown kid triggers at most one refresh per MinRefresh so key rotation
// is picked up without letting a caller drive unbounded fetches.
type RemoteKeySet struct {
	URL        string
	Client     *http.Client
	MinRefresh time.Duration

	mu          sync.Mutex
	keys        map[string]ed25519.PublicKey
	lastRefresh time.Time
	now         func() time.Time
}

// NewRemoteKeySet builds a remote key set; the first fetch happens lazily.
func NewRemoteKeySet(url string, client *http.Client) *RemoteKeySet {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &RemoteKeySet{URL: url, Client: client, MinRefresh: time.Minute, now: time.Now}
}

// Key implements KeySet.
func (r *RemoteKeySet) Key(kid string) (ed25519.PublicKey, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[kid]; ok {
		return k, true, nil
	}
	if r.keys != nil && r.now().Sub(r.lastRefresh) < r.MinRefresh {
		return nil, false, nil
	}
	if err := r.refreshLocked(); err != nil {
		if r.keys == nil {
			return nil, false, err
		}
		// A stale cache still answers for known kids; an unknown kid during
		// an outage stays unknown (fail closed) rather than erroring.
		return nil, false, nil
	}
	k, ok := r.keys[kid]
	return k, ok, nil
}

func (r *RemoteKeySet) refreshLocked() error {
	r.lastRefresh = r.now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return err
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	keys, err := ParseJWKS(data)
	if err != nil {
		return err
	}
	r.keys = keys
	return nil
}

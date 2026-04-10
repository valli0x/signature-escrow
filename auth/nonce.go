package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	nonceLength = 16
	nonceTTL    = 5 * time.Minute
)

type nonceEntry struct {
	nonce     string
	expiresAt time.Time
}

// NonceStore manages nonces for MetaMask sign-in.
type NonceStore struct {
	mu     sync.RWMutex
	nonces map[string]nonceEntry // address -> nonce
}

func NewNonceStore() *NonceStore {
	return &NonceStore{
		nonces: make(map[string]nonceEntry),
	}
}

// Generate creates a new nonce for the given address.
func (ns *NonceStore) Generate(address string) (string, error) {
	b := make([]byte, nonceLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)

	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.nonces[strings.ToLower(address)] = nonceEntry{
		nonce:     nonce,
		expiresAt: time.Now().Add(nonceTTL),
	}

	return nonce, nil
}

// Verify checks and consumes the nonce for the given address.
func (ns *NonceStore) Verify(address, nonce string) bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	key := strings.ToLower(address)
	entry, ok := ns.nonces[key]
	if !ok {
		return false
	}

	delete(ns.nonces, key)

	if time.Now().After(entry.expiresAt) {
		return false
	}

	return entry.nonce == nonce
}

// Cleanup removes expired nonces.
func (ns *NonceStore) Cleanup() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now()
	for addr, entry := range ns.nonces {
		if now.After(entry.expiresAt) {
			delete(ns.nonces, addr)
		}
	}
}

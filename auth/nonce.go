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

type NonceStore struct {
	mu     sync.RWMutex
	nonces map[string]nonceEntry
}

func NewNonceStore() *NonceStore {
	return &NonceStore{
		nonces: make(map[string]nonceEntry),
	}
}

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

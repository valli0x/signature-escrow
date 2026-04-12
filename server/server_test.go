package server

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/valli0x/signature-escrow/storage"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	storConf := map[string]string{"path": t.TempDir()}
	fileStor, err := storage.NewFileStorage(storConf, logger)
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(&ServerConfig{
		Addr:      ":0",
		Stor:      fileStor,
		Logger:    logger,
		JWTSecret: []byte("test-secret"),
	})

	return httptest.NewServer(srv.routes())
}

func postJSON(url string, body interface{}, token string) (*http.Response, map[string]interface{}, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(data, &result)

	return resp, result, nil
}

func TestAuthFlow(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Generate test Ethereum key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	// Step 1: Get nonce
	resp, result, err := postJSON(ts.URL+"/v1/auth/nonce", map[string]string{
		"address": address,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("nonce: expected 200, got %d: %v", resp.StatusCode, result)
	}

	nonce := result["nonce"].(string)
	message := result["message"].(string)
	t.Logf("nonce: %s", nonce)
	t.Logf("message: %s", message)

	// Step 2: Sign message with private key (simulates MetaMask personal_sign)
	msgHash := accounts.TextHash([]byte(message))
	sig, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	// MetaMask adds 27 to v
	sig[64] += 27
	signature := "0x" + hex.EncodeToString(sig)

	// Step 3: Login
	resp, result, err = postJSON(ts.URL+"/v1/auth/login", map[string]string{
		"address":   address,
		"signature": signature,
		"nonce":     nonce,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("login: expected 200, got %d: %v", resp.StatusCode, result)
	}

	token := result["token"].(string)
	returnedAddr := result["address"].(string)
	t.Logf("token: %s...", token[:20])
	t.Logf("address: %s", returnedAddr)

	if returnedAddr == "" {
		t.Fatal("empty address in login response")
	}

	// Step 4: Access protected endpoint without token — should fail
	resp, result, err = postJSON(ts.URL+"/v1/escrow", map[string]string{
		"test": "data",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("escrow without auth: expected 401, got %d", resp.StatusCode)
	}
	t.Log("escrow without auth correctly rejected")

	// Step 5: Access protected endpoint with token — should work
	resp, result, err = postJSON(ts.URL+"/v1/escrow", map[string]string{
		"alg":  "ecdsa",
		"id":   "test-escrow-id",
		"pub":  hex.EncodeToString(crypto.CompressPubkey(&privateKey.PublicKey)),
		"hash": hex.EncodeToString(msgHash),
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	// First escrow submission — stores flower, returns 204 No Content
	if resp.StatusCode != 204 {
		t.Fatalf("escrow first submit: expected 204, got %d: %v", resp.StatusCode, result)
	}
	t.Log("escrow first submission accepted (204)")
}

func TestEscrowExchange(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	// Generate two participants
	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	addrA := crypto.PubkeyToAddress(keyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(keyB.PublicKey).Hex()

	// Auth both
	tokenA := authenticate(t, ts.URL, keyA, addrA)
	tokenB := authenticate(t, ts.URL, keyB, addrB)

	// Common escrow data
	escrowID := "test-escrow-exchange"
	hashA := crypto.Keccak256([]byte("tx-data-A"))
	hashB := crypto.Keccak256([]byte("tx-data-B"))
	pubA := crypto.CompressPubkey(&keyA.PublicKey)
	pubB := crypto.CompressPubkey(&keyB.PublicKey)

	// A signs B's hash, B signs A's hash (cross-signatures for escrow)
	sigAforB, _ := crypto.Sign(hashB, keyA) // A signs B's hash
	sigBforA, _ := crypto.Sign(hashA, keyB) // B signs A's hash

	// Step 1: A submits flower
	resp, result, err := postJSON(ts.URL+"/v1/escrow", map[string]string{
		"alg":  "ecdsa",
		"id":   escrowID,
		"pub":  hex.EncodeToString(pubA),
		"hash": hex.EncodeToString(hashA),
		"sig":  hex.EncodeToString(sigBforA), // B's signature over A's hash
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("A submit: expected 204, got %d: %v", resp.StatusCode, result)
	}
	t.Log("A submitted flower")

	// Step 2: B submits flower
	resp, result, err = postJSON(ts.URL+"/v1/escrow", map[string]string{
		"alg":  "ecdsa",
		"id":   escrowID,
		"pub":  hex.EncodeToString(pubB),
		"hash": hex.EncodeToString(hashB),
		"sig":  hex.EncodeToString(sigAforB), // A's signature over B's hash
	}, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("B submit response: status=%d body=%v", resp.StatusCode, result)

	if resp.StatusCode == 200 && result != nil {
		if sig, ok := result["signature"]; ok {
			t.Logf("escrow exchange complete, B received signature: %s", sig)
		}
	}
}

func authenticate(t *testing.T, baseURL string, key *ecdsa.PrivateKey, address string) string {
	t.Helper()

	// Get nonce
	_, result, err := postJSON(baseURL+"/v1/auth/nonce", map[string]string{
		"address": address,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	nonce := result["nonce"].(string)
	message := result["message"].(string)

	// Sign
	msgHash := accounts.TextHash([]byte(message))
	sig, err := crypto.Sign(msgHash, key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27

	// Login
	_, result, err = postJSON(baseURL+"/v1/auth/login", map[string]string{
		"address":   address,
		"signature": fmt.Sprintf("0x%s", hex.EncodeToString(sig)),
		"nonce":     nonce,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	token, ok := result["token"].(string)
	if !ok || token == "" {
		t.Fatalf("auth failed for %s: %v", address, result)
	}

	return token
}

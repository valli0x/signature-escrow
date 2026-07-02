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

func getJSON(url string, token string) (*http.Response, map[string]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
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

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

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

	msgHash := accounts.TextHash([]byte(message))
	sig, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	signature := "0x" + hex.EncodeToString(sig)

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

	resp, result, err = postJSON(ts.URL+"/v1/escrow", map[string]string{
		"alg":  "ecdsa",
		"id":   "test-escrow-id",
		"pub":  hex.EncodeToString(crypto.CompressPubkey(&privateKey.PublicKey)),
		"hash": hex.EncodeToString(msgHash),
	}, token)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("escrow first submit: expected 200, got %d: %v", resp.StatusCode, result)
	}
	if status, _ := result["status"].(string); status != "pending" {
		t.Fatalf("escrow first submit: expected status=pending, got %v", result)
	}
	t.Log("escrow first submission accepted (pending)")
}

func TestEscrowExchange(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	addrA := crypto.PubkeyToAddress(keyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(keyB.PublicKey).Hex()

	tokenA := authenticate(t, ts.URL, keyA, addrA)
	tokenB := authenticate(t, ts.URL, keyB, addrB)

	escrowID := "test-escrow-exchange"
	hashA := crypto.Keccak256([]byte("tx-data-A"))
	hashB := crypto.Keccak256([]byte("tx-data-B"))
	pubA := crypto.CompressPubkey(&keyA.PublicKey)
	pubB := crypto.CompressPubkey(&keyB.PublicKey)

	sigAforB, _ := crypto.Sign(hashB, keyA)
	sigBforA, _ := crypto.Sign(hashA, keyB)

	resp, result, err := postJSON(ts.URL+"/v1/escrow", map[string]string{
		"alg":  "ecdsa",
		"id":   escrowID,
		"pub":  hex.EncodeToString(pubA),
		"hash": hex.EncodeToString(hashA),
		"sig":  hex.EncodeToString(sigBforA),
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("A submit: expected 200, got %d: %v", resp.StatusCode, result)
	}
	if status, _ := result["status"].(string); status != "pending" {
		t.Fatalf("A submit: expected status=pending, got %v", result)
	}
	t.Log("A submitted flower (pending)")

	resp, result, err = postJSON(ts.URL+"/v1/escrow", map[string]string{
		"alg":  "ecdsa",
		"id":   escrowID,
		"pub":  hex.EncodeToString(pubB),
		"hash": hex.EncodeToString(hashB),
		"sig":  hex.EncodeToString(sigAforB),
	}, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("B submit response: status=%d body=%v", resp.StatusCode, result)

	if resp.StatusCode == 200 {
		if status, _ := result["status"].(string); status == "complete" {
			sig, ok := result["signature"].(string)
			if !ok || sig == "" {
				t.Fatalf("expected partner signature on complete, got %v", result)
			}
			t.Logf("escrow exchange complete, B received partner signature: %s", sig)
		}
	}
}

func TestPairingFlow(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	addrA := crypto.PubkeyToAddress(keyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(keyB.PublicKey).Hex()

	tokenA := authenticate(t, ts.URL, keyA, addrA)
	tokenB := authenticate(t, ts.URL, keyB, addrB)

	resp, result, err := postJSON(ts.URL+"/v1/pair/create", map[string]string{
		"partner": addrB,
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("pair create: expected 200, got %d: %v", resp.StatusCode, result)
	}
	pairID := result["id"].(string)
	t.Logf("pair created: id=%s initiator=%s partner=%s status=%s",
		pairID, result["initiator"], result["partner"], result["status"])

	if result["status"] != "pending" {
		t.Fatalf("expected status pending, got %s", result["status"])
	}

	resp, result, err = getJSON(ts.URL+"/v1/pair/pending", tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("pair pending: expected 200, got %d: %v", resp.StatusCode, result)
	}
	incoming := result["incoming"].([]interface{})
	if len(incoming) != 1 {
		t.Fatalf("B should have 1 incoming pair, got %d", len(incoming))
	}
	t.Logf("B sees incoming pair: %v", incoming[0])

	resp, result, err = getJSON(ts.URL+"/v1/pair/pending", tokenA)
	if err != nil {
		t.Fatal(err)
	}
	outgoing := result["outgoing"].([]interface{})
	if len(outgoing) != 1 {
		t.Fatalf("A should have 1 outgoing pair, got %d", len(outgoing))
	}
	t.Logf("A sees outgoing pair: %v", outgoing[0])

	resp, _, err = postJSON(ts.URL+"/v1/pair/accept", map[string]string{
		"id": pairID,
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("A accept: expected 403, got %d", resp.StatusCode)
	}
	t.Log("A correctly cannot accept own pair")

	resp, result, err = postJSON(ts.URL+"/v1/pair/accept", map[string]string{
		"id": pairID,
	}, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("B accept: expected 200, got %d: %v", resp.StatusCode, result)
	}
	if result["status"] != "accepted" {
		t.Fatalf("expected status accepted, got %s", result["status"])
	}
	t.Logf("pair accepted: id=%s status=%s", result["id"], result["status"])

	resp, _, err = postJSON(ts.URL+"/v1/pair/create", map[string]string{
		"partner": addrA,
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("self-pair: expected 400, got %d", resp.StatusCode)
	}
	t.Log("self-pairing correctly rejected")

	resp, result, err = postJSON(ts.URL+"/v1/pair/create", map[string]string{
		"partner": addrB,
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("duplicate pair: expected 200, got %d", resp.StatusCode)
	}
	if result["status"] != "accepted" {
		t.Fatalf("duplicate should return accepted, got %s", result["status"])
	}
	t.Log("duplicate pair correctly returns existing")

	resp, _, err = postJSON(ts.URL+"/v1/pair/create", map[string]string{
		"partner": addrB,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("no auth: expected 401, got %d", resp.StatusCode)
	}
	t.Log("unauthenticated pair create correctly rejected")
}

func TestMailboxFlow(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()

	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	addrA := crypto.PubkeyToAddress(keyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(keyB.PublicKey).Hex()

	tokenA := authenticate(t, ts.URL, keyA, addrA)
	tokenB := authenticate(t, ts.URL, keyB, addrB)

	resp, result, _ := postJSON(ts.URL+"/v1/pair/create", map[string]string{
		"partner": addrB,
	}, tokenA)
	if resp.StatusCode != 200 {
		t.Fatalf("pair create failed: %v", result)
	}
	pairID := result["id"].(string)

	postJSON(ts.URL+"/v1/pair/accept", map[string]string{"id": pairID}, tokenB)

	resp, result, err := postJSON(ts.URL+"/v1/mailbox/send", map[string]interface{}{
		"to":      addrB,
		"pair_id": pairID,
		"type":    "keygen_request",
		"body":    map[string]interface{}{"session_id": "sess123", "network": "eth", "index": 1},
	}, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("mailbox send: expected 200, got %d: %v", resp.StatusCode, result)
	}
	msgID := result["id"].(string)
	t.Logf("message sent: id=%s", msgID)

	resp, result, err = getJSON(ts.URL+"/v1/mailbox/pending", tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("mailbox pending: expected 200, got %d", resp.StatusCode)
	}
	messages := result["messages"].([]interface{})
	if len(messages) != 1 {
		t.Fatalf("B should have 1 message, got %d", len(messages))
	}
	msg := messages[0].(map[string]interface{})
	t.Logf("B received: type=%s from=%s", msg["type"], msg["from"])

	if msg["type"] != "keygen_request" {
		t.Fatalf("expected keygen_request, got %s", msg["type"])
	}

	resp, result, _ = getJSON(ts.URL+"/v1/mailbox/pending", tokenA)
	aMessages := result["messages"].([]interface{})
	if len(aMessages) != 0 {
		t.Fatalf("A should have 0 messages, got %d", len(aMessages))
	}
	t.Log("A inbox correctly empty")

	keyC, _ := crypto.GenerateKey()
	addrC := crypto.PubkeyToAddress(keyC.PublicKey).Hex()
	tokenC := authenticate(t, ts.URL, keyC, addrC)

	resp, _, _ = postJSON(ts.URL+"/v1/mailbox/send", map[string]interface{}{
		"to":      addrB,
		"pair_id": pairID,
		"type":    "keygen_request",
		"body":    map[string]interface{}{},
	}, tokenC)
	if resp.StatusCode != 403 {
		t.Fatalf("outsider send: expected 403, got %d", resp.StatusCode)
	}
	t.Log("outsider correctly rejected")

	resp, _, err = postJSON(ts.URL+"/v1/mailbox/ack", map[string]string{
		"id": msgID,
	}, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("mailbox ack: expected 204, got %d", resp.StatusCode)
	}

	resp, result, _ = getJSON(ts.URL+"/v1/mailbox/pending", tokenB)
	messages = result["messages"].([]interface{})
	if len(messages) != 0 {
		t.Fatalf("B should have 0 messages after ack, got %d", len(messages))
	}
	t.Log("message acknowledged and removed")
}

func authenticate(t *testing.T, baseURL string, key *ecdsa.PrivateKey, address string) string {
	t.Helper()

	_, result, err := postJSON(baseURL+"/v1/auth/nonce", map[string]string{
		"address": address,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	nonce := result["nonce"].(string)
	message := result["message"].(string)

	msgHash := accounts.TextHash([]byte(message))
	sig, err := crypto.Sign(msgHash, key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27

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

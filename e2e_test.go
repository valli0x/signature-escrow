package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

const baseURL = "http://localhost:8282"

func TestE2E_AuthAndPairing(t *testing.T) {
	// Generate two test wallets
	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	addrA := crypto.PubkeyToAddress(keyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(keyB.PublicKey).Hex()

	t.Logf("Participant A: %s", addrA)
	t.Logf("Participant B: %s", addrB)

	// === AUTH ===

	// Step 1: Get nonce for A
	nonceRespA := post(t, "/v1/auth/nonce", map[string]string{"address": addrA}, "")
	nonceA := nonceRespA["nonce"].(string)
	messageA := nonceRespA["message"].(string)
	t.Logf("A nonce: %s", nonceA)

	// Step 2: Sign message with A's key
	sigA := signMessage(t, messageA, keyA)
	t.Logf("A signature: %s", sigA)

	// Step 3: Login A
	loginRespA := post(t, "/v1/auth/login", map[string]interface{}{
		"address":   addrA,
		"signature": sigA,
		"nonce":     nonceA,
	}, "")
	tokenA := loginRespA["token"].(string)
	t.Logf("A token: %s...%s", tokenA[:20], tokenA[len(tokenA)-10:])
	t.Logf("A authenticated as: %s", loginRespA["address"])

	// Step 4: Same for B
	nonceRespB := post(t, "/v1/auth/nonce", map[string]string{"address": addrB}, "")
	nonceB := nonceRespB["nonce"].(string)
	messageB := nonceRespB["message"].(string)

	sigB := signMessage(t, messageB, keyB)
	loginRespB := post(t, "/v1/auth/login", map[string]interface{}{
		"address":   addrB,
		"signature": sigB,
		"nonce":     nonceB,
	}, "")
	tokenB := loginRespB["token"].(string)
	t.Logf("B authenticated as: %s", loginRespB["address"])

	// === PAIRING ===

	// Step 5: A creates pair with B
	pairResp := post(t, "/v1/pair/create", map[string]string{
		"partner": addrB,
	}, tokenA)
	t.Logf("Pair created: id=%s status=%s", pairResp["id"], pairResp["status"])

	if pairResp["status"] != "pending" {
		t.Fatalf("expected pending, got %s", pairResp["status"])
	}

	// Step 6: B checks pending
	pendingResp := get(t, "/v1/pair/pending", tokenB)
	incoming := pendingResp["incoming"].([]interface{})
	if len(incoming) == 0 {
		t.Fatal("B should see incoming pair")
	}
	inPair := incoming[0].(map[string]interface{})
	t.Logf("B sees incoming: initiator=%s status=%s", inPair["initiator"], inPair["status"])

	// Step 7: B accepts
	acceptResp := post(t, "/v1/pair/accept", map[string]string{
		"id": pairResp["id"].(string),
	}, tokenB)
	t.Logf("Pair accepted: status=%s", acceptResp["status"])

	if acceptResp["status"] != "accepted" {
		t.Fatalf("expected accepted, got %s", acceptResp["status"])
	}

	// Step 8: A checks — should see accepted
	pendingA := get(t, "/v1/pair/pending", tokenA)
	outgoing := pendingA["outgoing"].([]interface{})
	outPair := outgoing[0].(map[string]interface{})
	t.Logf("A sees outgoing: status=%s", outPair["status"])

	if outPair["status"] != "accepted" {
		t.Fatalf("A should see accepted, got %s", outPair["status"])
	}

	t.Log("=== E2E AUTH + PAIRING PASSED ===")
}

func signMessage(t *testing.T, message string, key *ecdsa.PrivateKey) string {
	t.Helper()
	hash := accounts.TextHash([]byte(message))
	sig, err := crypto.Sign(hash, key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27 // MetaMask format
	return fmt.Sprintf("0x%x", sig)
}

func post(t *testing.T, path string, body interface{}, token string) map[string]interface{} {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", baseURL+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		t.Fatalf("POST %s: %d %s", path, resp.StatusCode, string(raw))
	}

	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return result
}

func get(t *testing.T, path string, token string) map[string]interface{} {
	t.Helper()
	req, _ := http.NewRequest("GET", baseURL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, string(raw))
	}

	var result map[string]interface{}
	json.Unmarshal(raw, &result)
	return result
}

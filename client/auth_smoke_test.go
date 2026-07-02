package client

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	ethaccounts "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/valli0x/signature-escrow/config"
	"github.com/valli0x/signature-escrow/storage"
)

func mkClient(t *testing.T) (*Client, *httptest.Server) {
	dir := t.TempDir()
	stor, err := storage.NewFileStorage(map[string]string{"path": dir}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(&ClientConfig{
		Addr:        ":0",
		Stor:        stor,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Env:         &config.Env{},
		StoragePass: "smoke-pass",
		JWTSecret:   "smoke-secret",
	})
	ts := httptest.NewServer(c.routes())
	t.Cleanup(ts.Close)
	return c, ts
}

func doLogin(t *testing.T, ts *httptest.Server, addr string, sign func(msg string) string) (int, string) {
	nb, _ := json.Marshal(NonceRequest{Address: addr})
	resp, err := http.Post(ts.URL+"/v1/auth/nonce", "application/json", bytes.NewReader(nb))
	if err != nil {
		t.Fatal(err)
	}
	var nr NonceResponse
	json.NewDecoder(resp.Body).Decode(&nr)
	resp.Body.Close()
	lb, _ := json.Marshal(LoginRequest{Address: addr, Signature: sign(nr.Message), Nonce: nr.Nonce})
	resp, err = http.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(lb))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var lr LoginResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	return resp.StatusCode, lr.Token
}

func TestClientAuthOwnerBinding(t *testing.T) {
	_, ts := mkClient(t)

	ownerKeyP, _ := crypto.GenerateKey()
	ownerAddr := crypto.PubkeyToAddress(ownerKeyP.PublicKey).Hex()
	signOwner := func(msg string) string {
		h := ethaccounts.TextHash([]byte(msg))
		sig, _ := crypto.Sign(h, ownerKeyP)
		return hexutil.Encode(sig)
	}

	strangerKeyP, _ := crypto.GenerateKey()
	strangerAddr := crypto.PubkeyToAddress(strangerKeyP.PublicKey).Hex()
	signStranger := func(msg string) string {
		h := ethaccounts.TextHash([]byte(msg))
		sig, _ := crypto.Sign(h, strangerKeyP)
		return hexutil.Encode(sig)
	}

	resp, _ := http.Get(ts.URL + "/v1/identity")
	var id IdentityResponse
	json.NewDecoder(resp.Body).Decode(&id)
	resp.Body.Close()
	if id.Bound || id.HasKeys {
		t.Fatalf("expected unbound fresh client, got %+v", id)
	}

	resp, _ = http.Get(ts.URL + "/v1/accounts/list")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	code, token := doLogin(t, ts, ownerAddr, signOwner)
	if code != http.StatusOK || token == "" {
		t.Fatalf("owner login failed: code=%d", code)
	}

	resp, _ = http.Get(ts.URL + "/v1/identity")
	json.NewDecoder(resp.Body).Decode(&id)
	resp.Body.Close()
	if !id.Bound || normAddr(id.Address) != normAddr(ownerAddr) {
		t.Fatalf("expected bound to owner, got %+v", id)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/v1/accounts/list", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner protected call failed: %d", resp.StatusCode)
	}
	resp.Body.Close()

	code, _ = doLogin(t, ts, strangerAddr, signStranger)
	if code != http.StatusForbidden {
		t.Fatalf("expected stranger login 403, got %d", code)
	}

	code, _ = doLogin(t, ts, ownerAddr, signOwner)
	if code != http.StatusOK {
		t.Fatalf("owner re-login failed: %d", code)
	}
}

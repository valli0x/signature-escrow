package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"sync"
	"testing"

	ethaccounts "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	mpsecdsa "github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
)

func authToken(t *testing.T, tsURL string) (string, string) {
	t.Helper()
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.PubkeyToAddress(priv.PublicKey).Hex()
	_, res, err := postJSON(tsURL+"/v1/auth/nonce", map[string]string{"address": addr}, "")
	if err != nil {
		t.Fatal(err)
	}
	msg := res["message"].(string)
	nonce := res["nonce"].(string)
	h := ethaccounts.TextHash([]byte(msg))
	sig, _ := crypto.Sign(h, priv)
	sig[64] += 27
	_, res, err = postJSON(tsURL+"/v1/auth/login", map[string]string{
		"address": addr, "signature": "0x" + hex.EncodeToString(sig), "nonce": nonce,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := res["token"].(string)
	if tok == "" {
		t.Fatal("no token")
	}
	return tok, addr
}

// cmpAccount builds a shared-account pubkey (compressed hex) + a CMP-format
// signature (hex) over the given hash — the exact bytes the app deposits.
func cmpAccount(t *testing.T, hash []byte) (pubHex, sigHex string) {
	t.Helper()
	group := curve.Secp256k1{}
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	m := curve.FromHash(group, hash)
	for i := 0; i < 500; i++ {
		k := sample.Scalar(rand.Reader, group)
		R := k.ActOnBase()
		r := R.XScalar()
		s := group.NewScalar().Set(k).Invert().Mul(group.NewScalar().Set(m).Add(group.NewScalar().Set(r).Mul(x)))
		if s.IsZero() {
			continue
		}
		sig := &mpsecdsa.Signature{R: R, S: s}
		if !sig.Verify(X, hash) {
			continue
		}
		b, err := mpccmp.GetSigByte(sig)
		if err != nil {
			t.Fatal(err)
		}
		pb, err := X.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(pb), hex.EncodeToString(b)
	}
	t.Fatal("could not build a CMP signature")
	return "", ""
}

func deposit(tsURL, token, id, alg, pub, hash, sig string) (*http.Response, map[string]interface{}) {
	resp, res, _ := postJSON(tsURL+"/v1/escrow", map[string]string{
		"alg": alg, "id": id, "pub": pub, "hash": hash, "sig": sig,
	}, token)
	return resp, res
}

func check(tsURL, token, id, pub string) (*http.Response, map[string]interface{}) {
	resp, res, _ := postJSON(tsURL+"/v1/escrow/check", map[string]string{"id": id, "pub": pub}, token)
	return resp, res
}

// ---- the full swap fixture: two shared accounts A and B, each with its own
// hash; each party deposits {own pub, own hash, COUNTERPARTY's completed sig}.
type swap struct {
	pubA, hashA, sigA string // sigA validates hashA under pubA (Alice's withdrawal)
	pubB, hashB, sigB string
}

func newSwap(t *testing.T) swap {
	hA := sha256.Sum256([]byte("alice withdrawal"))
	hB := sha256.Sum256([]byte("bob withdrawal"))
	pubA, sigA := cmpAccount(t, hA[:])
	pubB, sigB := cmpAccount(t, hB[:])
	return swap{
		pubA: pubA, hashA: hex.EncodeToString(hA[:]), sigA: sigA,
		pubB: pubB, hashB: hex.EncodeToString(hB[:]), sigB: sigB,
	}
}

// 1. Happy path: both deposit valid cross-signatures → each is released ITS OWN
// withdrawal signature, and it verifies.
func TestEscrowHappyPathRelease(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	tokB, _ := authToken(t, ts.URL)
	id := "swap-happy"

	// Alice deposits her pub/hash carrying Bob's sig; still pending (one flower).
	resp, res := deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	if resp.StatusCode != 200 || res["status"] != "pending" {
		t.Fatalf("alice deposit: %d %v", resp.StatusCode, res)
	}
	// Bob deposits → pollinates → complete, returns Bob's own withdrawal sig.
	resp, res = deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA)
	if resp.StatusCode != 200 || res["status"] != "complete" {
		t.Fatalf("bob deposit expected complete: %d %v", resp.StatusCode, res)
	}
	assertReleasedSig(t, res, sw.pubB, sw.hashB)

	// Alice polls and gets her own withdrawal sig.
	resp, res = check(ts.URL, tokA, id, sw.pubA)
	if resp.StatusCode != 200 || res["status"] != "complete" {
		t.Fatalf("alice check expected complete: %d %v", resp.StatusCode, res)
	}
	assertReleasedSig(t, res, sw.pubA, sw.hashA)
}

func assertReleasedSig(t *testing.T, res map[string]interface{}, pubHex, hashHex string) {
	t.Helper()
	b64, _ := res["signature"].(string)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("bad base64 sig: %v", err)
	}
	sig, err := mpccmp.FromSigByte(raw)
	if err != nil {
		t.Fatalf("released sig not CMP-parseable: %v", err)
	}
	pubB, _ := hex.DecodeString(pubHex)
	pt := &curve.Secp256k1Point{}
	if err := pt.UnmarshalBinary(pubB); err != nil {
		t.Fatal(err)
	}
	hb, _ := hex.DecodeString(hashHex)
	if !sig.Verify(pt, hb) {
		t.Fatal("released signature does not verify against the receiver's own pub/hash")
	}
}

// 2. Invalid/mismatched signatures must NEVER release (stay pending forever).
func TestEscrowMismatchedSigsNeverRelease(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	tokB, _ := authToken(t, ts.URL)
	id := "swap-bad"
	// Deposit each party's OWN sig under OWN pub (the naive/wrong pairing) —
	// pollination cross-check fails, so nothing is ever released.
	deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigA)
	resp, res := deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigB)
	if resp.StatusCode != 200 || res["status"] != "pending" {
		t.Fatalf("mismatched sigs must stay pending, got %d %v", resp.StatusCode, res)
	}
	_, res = check(ts.URL, tokA, id, sw.pubA)
	if res["status"] == "complete" {
		t.Fatal("released a signature despite failed cross-validation")
	}
}

// 3. Auth is mandatory — no token, no escrow.
func TestEscrowRequiresAuth(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	resp, _ := deposit(ts.URL, "", "swap-x", "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deposit without token expected 401, got %d", resp.StatusCode)
	}
	resp, _ = check(ts.URL, "", "swap-x", sw.pubA)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("check without token expected 401, got %d", resp.StatusCode)
	}
}

// 4. A stranger cannot overwrite a legitimate flower (grief the swap).
func TestEscrowForeignOverwriteRejected(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	tokM, _ := authToken(t, ts.URL) // mallory
	id := "swap-grief"
	deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	// Mallory tries to overwrite Alice's slot (same pub) with garbage.
	resp, res := deposit(ts.URL, tokM, id, "ecdsa", sw.pubA, sw.hashA, "deadbeef")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("foreign overwrite expected 409, got %d %v", resp.StatusCode, res)
	}
	// Alice's flower must be intact: complete the swap normally and release.
	tokB, _ := authToken(t, ts.URL)
	deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA)
	_, res = check(ts.URL, tokA, id, sw.pubA)
	if res["status"] != "complete" {
		t.Fatalf("alice's flower was corrupted by the overwrite attempt: %v", res)
	}
}

// 5. The deposited signature is immutable; a re-post with different bytes fails,
// an identical re-post is idempotent.
func TestEscrowSigImmutable(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	id := "swap-immut"
	deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	resp, _ := deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, "0011")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("changing a deposited sig expected 409, got %d", resp.StatusCode)
	}
	resp, _ = deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	if resp.StatusCode != 200 {
		t.Fatalf("idempotent identical re-post expected 200, got %d", resp.StatusCode)
	}
}

// 6. One depositor cannot occupy both slots (self-swap to drain).
func TestEscrowOneDepositorBothSlotsRejected(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	id := "swap-selfboth"
	deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	resp, res := deposit(ts.URL, tokA, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("same depositor both slots expected 409, got %d %v", resp.StatusCode, res)
	}
}

// 7. A third participant is rejected, not silently dropped.
func TestEscrowThirdParticipantRejected(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	tokB, _ := authToken(t, ts.URL)
	tokC, _ := authToken(t, ts.URL)
	id := "swap-third"
	deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA)
	hC := sha256.Sum256([]byte("carol"))
	pubC, sigC := cmpAccount(t, hC[:])
	resp, res := deposit(ts.URL, tokC, id, "ecdsa", pubC, hex.EncodeToString(hC[:]), sigC)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("third participant expected 409, got %d %v", resp.StatusCode, res)
	}
}

// 8. Release is authorized: only the depositor of a slot can poll its signature.
func TestEscrowReleaseOnlyToDepositor(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	tokB, _ := authToken(t, ts.URL)
	tokM, _ := authToken(t, ts.URL)
	id := "swap-authz"
	deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA)
	// Mallory polls Alice's pub → forbidden.
	resp, _ := check(ts.URL, tokM, id, sw.pubA)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stranger polling alice's slot expected 403, got %d", resp.StatusCode)
	}
	// Even Bob (a legit participant) cannot poll ALICE's pub.
	resp, _ = check(ts.URL, tokB, id, sw.pubA)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob polling alice's slot expected 403, got %d", resp.StatusCode)
	}
	// Bob polling his OWN pub is fine.
	_, res := check(ts.URL, tokB, id, sw.pubB)
	if res["status"] != "complete" {
		t.Fatalf("bob polling his own slot should release: %v", res)
	}
}

// 9. Concurrency: many racing deposits under one id must not corrupt state —
// exactly the two legitimate flowers survive; extras are rejected, never clobber.
func TestEscrowConcurrentDepositsNoClobber(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokA, _ := authToken(t, ts.URL)
	tokB, _ := authToken(t, ts.URL)
	id := "swap-race"

	// The two legit parties deposit concurrently many times (idempotent) —
	// the read-modify-write under escrowMu must never lose or clobber a flower.
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB) }()
		go func() { defer wg.Done(); deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA) }()
	}
	wg.Wait()

	// Whatever the interleaving, the two legit parties must end up releasable
	// with sigs that verify — no attacker write survived in a legit slot.
	_, resA := check(ts.URL, tokA, id, sw.pubA)
	_, resB := check(ts.URL, tokB, id, sw.pubB)
	if resA["status"] != "complete" || resB["status"] != "complete" {
		t.Fatalf("after race, legit release broke: A=%v B=%v", resA, resB)
	}
	assertReleasedSig(t, resA, sw.pubA, sw.hashA)
	assertReleasedSig(t, resB, sw.pubB, sw.hashB)
}

// 10. Slot-squatting is a griefing bound, NOT theft. An attacker who learns the
// (96-bit, mailbox-private) exchange id can squat a slot and block the victim —
// but can NEVER extract a signature: pollination requires a valid cross-sig it
// cannot produce, and a release only ever goes to the slot's own depositor.
func TestEscrowSquatGriefsButCannotSteal(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Close()
	sw := newSwap(t)
	tokM, _ := authToken(t, ts.URL) // attacker who leaked the id
	tokA, _ := authToken(t, ts.URL) // real Alice
	tokB, _ := authToken(t, ts.URL) // real Bob
	id := "swap-squat"

	hM := sha256.Sum256([]byte("attacker"))
	_, sigM := cmpAccount(t, hM[:])

	// Attacker squats Alice's pub first.
	deposit(ts.URL, tokM, id, "ecdsa", sw.pubA, sw.hashA, sigM)
	// Real Alice is blocked (griefing) — documented residual, bounded by id secrecy.
	resp, _ := deposit(ts.URL, tokA, id, "ecdsa", sw.pubA, sw.hashA, sw.sigB)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected the squat to block Alice (409), got %d", resp.StatusCode)
	}
	// Bob completes his side; the attacker still cannot steal anything:
	deposit(ts.URL, tokB, id, "ecdsa", sw.pubB, sw.hashB, sw.sigA)
	// Attacker polling the slot they squatted: pollination can't validate their
	// bogus sig, so it stays pending forever — no signature is ever released.
	_, res := check(ts.URL, tokM, id, sw.pubA)
	if res["status"] == "complete" {
		t.Fatal("THEFT: attacker extracted a signature from a squatted slot")
	}
	// And Bob, though he deposited, gets nothing either (the swap is dead) — no
	// partial release that could leak a usable signature.
	_, res = check(ts.URL, tokB, id, sw.pubB)
	if res["status"] == "complete" {
		t.Fatal("released Bob's counterparty sig despite an invalid (squatted) flower")
	}
}

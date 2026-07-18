package validation

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
)

// makeSig manually constructs a valid ECDSA signature (R = kG, s = k⁻¹(m+rx))
// exactly like the CMP protocol output, so we can test the escrow validation
// formats without running MPC. Loops until the drawn s is high-s or low-s as
// requested (so both SigEthereum branches are covered).
func makeSig(t *testing.T, hash []byte, wantHighS bool) (*ecdsa.Signature, curve.Point) {
	t.Helper()
	group := curve.Secp256k1{}
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	m := curve.FromHash(group, hash)
	for i := 0; i < 200; i++ {
		k := sample.Scalar(rand.Reader, group)
		R := k.ActOnBase()
		r := R.XScalar()
		rx := group.NewScalar().Set(r).Mul(x)
		sum := group.NewScalar().Set(m).Add(rx)
		s := group.NewScalar().Set(k).Invert().Mul(sum)
		if s.IsZero() {
			continue
		}
		if s.(*curve.Secp256k1Scalar).IsOverHalfOrder() != wantHighS {
			continue
		}
		sig := &ecdsa.Signature{R: R, S: s}
		if !sig.Verify(X, hash) {
			t.Fatal("constructed signature does not verify")
		}
		return sig, X
	}
	t.Fatal("could not draw a signature with the requested s parity")
	return nil, nil
}

func pubBytes(t *testing.T, X curve.Point) []byte {
	t.Helper()
	b, err := X.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func copySig(sig *ecdsa.Signature) *ecdsa.Signature {
	group := curve.Secp256k1{}
	return &ecdsa.Signature{R: sig.R, S: group.NewScalar().Set(sig.S)}
}

// The escrow flower MUST carry the CMP-native encoding taken BEFORE
// SigEthereum: [33B compressed R point][32B S scalar].
func TestValidateAcceptsCMPFormat(t *testing.T) {
	h := sha256.Sum256([]byte("swap tx"))
	for _, highS := range []bool{false, true} {
		sig, X := makeSig(t, h[:], highS)
		cmpBytes, err := mpccmp.GetSigByte(copySig(sig))
		if err != nil {
			t.Fatal(err)
		}
		ok, err := Validate(ECDSA, pubBytes(t, X), h[:], cmpBytes)
		if err != nil {
			t.Fatalf("highS=%v: Validate errored on CMP format: %v", highS, err)
		}
		if !ok {
			t.Fatalf("highS=%v: Validate rejected a valid CMP-format signature", highS)
		}
	}
}

// Regression: the 65-byte Ethereum r||s||v encoding must NOT be deposited into
// escrow — Validate parses [33B point][32B scalar] and can never verify it.
// (This was the bug that left every ECDSA swap "pending" forever.)
func TestValidateRejectsEthereumFormat(t *testing.T) {
	h := sha256.Sum256([]byte("swap tx"))
	for _, highS := range []bool{false, true} {
		sig, X := makeSig(t, h[:], highS)
		ethBytes, err := mpccmp.SigEthereum(copySig(sig))
		if err != nil {
			t.Fatal(err)
		}
		ok, err := Validate(ECDSA, pubBytes(t, X), h[:], ethBytes)
		if err == nil && ok {
			t.Fatalf("highS=%v: Validate unexpectedly accepted the Ethereum r||s||v format", highS)
		}
	}
}

// mpccmp.SigEthereum mutates the signature in place (negates a high S AND
// flips R's parity to match), so the mutated pair (−R, −s) still verifies.
// The escrow deposit path captures GetSigByte BEFORE SigEthereum anyway
// (clearer semantics), but this pins the invariant that BOTH capture orders
// produce a Validate-able CMP signature — if SigEthereum is ever replaced by
// an implementation that negates only S, this test catches the break.
func TestEscrowSigValidAroundSigEthereum(t *testing.T) {
	h := sha256.Sum256([]byte("swap tx"))
	for _, highS := range []bool{false, true} {
		sig, X := makeSig(t, h[:], highS)

		before, err := mpccmp.GetSigByte(copySig(sig))
		if err != nil {
			t.Fatal(err)
		}
		ok, err := Validate(ECDSA, pubBytes(t, X), h[:], before)
		if err != nil || !ok {
			t.Fatalf("highS=%v: GetSigByte before SigEthereum must validate (ok=%v err=%v)", highS, ok, err)
		}

		mutated := copySig(sig)
		if _, err := mpccmp.SigEthereum(mutated); err != nil {
			t.Fatal(err)
		}
		after, err := mpccmp.GetSigByte(mutated)
		if err != nil {
			t.Fatal(err)
		}
		ok, err = Validate(ECDSA, pubBytes(t, X), h[:], after)
		if err != nil || !ok {
			t.Fatalf("highS=%v: GetSigByte after SigEthereum no longer validates (ok=%v err=%v) — SigEthereum stopped keeping R/S consistent", highS, ok, err)
		}
	}
}

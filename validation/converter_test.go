package validation

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
)

func TestConverterRoundTrip(t *testing.T) {
	h := sha256.Sum256([]byte("release path"))
	_ = rand.Reader
	for _, highS := range []bool{false, true} {
		sig, X := makeSig(t, h[:], highS)
		cmpBytes, err := mpccmp.GetSigByte(copySig(sig))
		if err != nil { t.Fatal(err) }
		parsed, err := mpccmp.FromSigByte(cmpBytes)
		if err != nil { t.Fatal(err) }
		eth, err := mpccmp.SigEthereum(parsed)
		if err != nil { t.Fatal(err) }
		if len(eth) != 65 { t.Fatalf("eth sig len %d", len(eth)) }
		if eth[64] != 0 && eth[64] != 1 { t.Fatalf("bad recovery id %d", eth[64]) }
		_ = X
		_ = curve.Secp256k1{}
	}
}

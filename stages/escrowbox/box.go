package escrowbox

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
)

type Escrow struct{}

func NewEscrow() {}

func (e *Escrow) Validate(alg SignaturesType, pub, hash, sig []byte) (bool, error) {
	switch alg {
	case ecdsaType:
		return crypto.VerifySignature(pub, hash, sig), nil
	case schnorrType:
		signature, err := schnorr.ParseSignature(sig)
		if err != nil {
			return false, err
		}
		pubECDSA, err := schnorr.ParsePubKey(pub)
		if err != nil {
			return false, nil
		}
		return signature.Verify(hash, pubECDSA), nil
	}
	return false, nil
}

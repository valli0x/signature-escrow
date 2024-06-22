package validation

import (
	"errors"

	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

type SignaturesType string

const (
	ECDSA SignaturesType = "ecdsa"
	Frost SignaturesType = "schnorr"
)

func Alg(alg string) SignaturesType {
	switch alg {
	case "frost":
		return Frost
	case "ecdsa":
		return ECDSA
	default:
		return ""
	}
}

func Validate(alg SignaturesType, p, h, s []byte) (bool, error) {
	switch alg {
	case ECDSA:
		if len(s) < 64 {
			return false, errors.New("signature size is less than 64")
		}

		sig := ecdsa.EmptySignature(curve.Secp256k1{})
		if err := sig.R.UnmarshalBinary(s[:33]); err != nil {
			return false, err
		}
		if err := sig.S.UnmarshalBinary(s[33:]); err != nil {
			return false, err
		}

		pub := &curve.Secp256k1Point{}
		if err := pub.UnmarshalBinary(p); err != nil {
			return false, err
		}

		return sig.Verify(pub, h), nil
	case Frost:
		var pub taproot.PublicKey = p
		return pub.Verify(s, h), nil
	default:
		return false, errors.New("unknown alg type")
	}
}

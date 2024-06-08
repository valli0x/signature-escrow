package mpccmp

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func EmptyConfig() *cmp.Config {
	return cmp.EmptyConfig(curve.Secp256k1{})
}

func EmptyPreSign() *ecdsa.PreSignature {
	return ecdsa.EmptyPreSignature(curve.Secp256k1{})
}

func MsgToHex(msg *protocol.Message) (string, error) {
	msgB, err := msg.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(msgB), nil
}

func HexToMsg(body string) (*protocol.Message, error) {
	b, err := hex.DecodeString(body)
	if err != nil {
		return nil, err
	}
	msg := &protocol.Message{}

	if err := msg.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return msg, err
}

func PrintAddressPubKeyECDSA(c *cmp.Config) error {
	publicKey, err := c.PublicPoint().MarshalBinary()
	if err != nil {
		return err
	}

	pubkeyECDSA, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		return err
	}

	pub := crypto.FromECDSAPub(pubkeyECDSA)
	address := crypto.PubkeyToAddress(*pubkeyECDSA).Hex()

	fmt.Printf("address: %s\n", address)
	fmt.Printf("public key: %s\n", hex.EncodeToString(pub))
	return nil
}

func GetSigByte(sig *ecdsa.Signature) ([]byte, error) {
	r, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 65)
	data = append(data, r...)
	data = append(data, s...)
	return data, nil
}

func FromSigByte(s []byte) (*ecdsa.Signature, error) {
	sig := ecdsa.EmptySignature(curve.Secp256k1{})
	if err := sig.R.UnmarshalBinary(s[:33]); err != nil {
		return nil, err
	}
	if err := sig.S.UnmarshalBinary(s[33:]); err != nil {
		return nil, err
	}
	return &sig, nil
}

func GetPublicKeyByte(c *cmp.Config) ([]byte, error) {
	publicKey, err := c.PublicPoint().MarshalBinary()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func GetAddress(c *cmp.Config) (string, error) {
	publicKey, err := c.PublicPoint().MarshalBinary()
	if err != nil {
		return "", err
	}
	publicKeyECDSA, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		return "", err
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return address, nil
}

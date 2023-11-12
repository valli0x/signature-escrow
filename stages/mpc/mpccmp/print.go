package mpccmp

import (
	"encoding/hex"
	"fmt"

	crypto_ecdsa "crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
)

func PrintAddressPubKeyECDSA(name string, c *cmp.Config) error {
	pubkeyECDSA, err := GetPubKeyFromConfigECDSA(c)
	if err != nil {
		return err
	}

	pub := crypto.FromECDSAPub(pubkeyECDSA)
	address := crypto.PubkeyToAddress(*pubkeyECDSA).Hex()

	fmt.Printf("address: %s\n", address)
	fmt.Printf("public key: %s\n", hex.EncodeToString(pub))
	return nil
}

func GetPubKeyFromConfigECDSA(keygenConfig *cmp.Config) (*crypto_ecdsa.PublicKey, error) {
	// get from address
	publicKey, _ := keygenConfig.PublicPoint().MarshalBinary()
	publicKeyECDSA, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		return nil, err
	}

	return publicKeyECDSA, nil
}

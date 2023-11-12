package mpcfrost

import (
	"encoding/hex"
	"fmt"

	crypto_ecdsa "crypto/ecdsa"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func PrintAddressPubKeyTaproot(name string, c *frost.TaprootConfig) error {
	pubkeyECDSA, err := GetPubKeyFromConfigTaproot(c)
	if err != nil {
		return err
	}

	pub := crypto.FromECDSAPub(pubkeyECDSA)
	address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub), &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	fmt.Printf("address: %s\n", address)
	fmt.Printf("public key: %s\n", hex.EncodeToString(pub))
	return nil
}

func GetPubKeyFromConfigTaproot(keygenConfig *frost.TaprootConfig) (*crypto_ecdsa.PublicKey, error) {
	publicKeyECDSA, err := schnorr.ParsePubKey(keygenConfig.PublicKey)
	if err != nil {
		return nil, err
	}

	return publicKeyECDSA.ToECDSA(), nil
}

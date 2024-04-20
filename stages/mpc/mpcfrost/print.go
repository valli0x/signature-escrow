package mpcfrost

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

func PrintAddressPubKeyTaproot(name string, c *frost.TaprootConfig) error {
	pub, err := schnorr.ParsePubKey(c.PublicKey)
	if err != nil {
		return err
	}

	witnessProg := btcutil.Hash160(pub.SerializeCompressed())
	address, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	fmt.Printf("address: %s\n", address)
	fmt.Printf("public key: %s\n", hex.EncodeToString(c.PublicKey))
	return nil
}

func GetPublicKeyByte(c *frost.TaprootConfig) ([]byte, error) {
	return c.PublicKey, nil
}

// SegWit address type
func GetAddress(c *frost.TaprootConfig) (*btcutil.AddressWitnessPubKeyHash, error) {
	pub, err := schnorr.ParsePubKey(c.PublicKey)
	if err != nil {
		return nil, err
	}

	witnessProg := btcutil.Hash160(pub.SerializeCompressed())
	address, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return address, nil
}

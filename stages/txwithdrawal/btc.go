package txwithdrawal

import (
	"encoding/hex"
	"math/big"

	"github.com/blockcypher/gobcy/v2"
)

func TxBTC(btcAPI gobcy.API, from, to string, amount int64) (*gobcy.TXSkel, []byte, error) {
	tx, err := btcAPI.NewTX(gobcy.TempNewTX(from, to, *big.NewInt(amount)), true)
	if err != nil {
		return nil, nil, err
	}

	hash, err := hex.DecodeString(tx.ToSign[0])
	if err != nil {
		return nil, nil, err
	}
	return &tx, hash, nil
}

func HashBTC(tx *gobcy.TXSkel) ([]byte, error) {
	return hex.DecodeString(tx.ToSign[0])
}

func WithSignatureBTC(tx *gobcy.TXSkel, sig []byte) (*gobcy.TXSkel, error) {
	tx.Signatures = append(tx.Signatures, hex.EncodeToString(sig))
	return tx, nil
}

func SendBTC(btcAPI gobcy.API, tx *gobcy.TXSkel) error {
	_, err := btcAPI.SendTX(*tx)
	if err != nil {
		return err
	}
	return nil
}

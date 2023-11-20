package txwithdrawal

import (
	"encoding/hex"
	"math/big"

	"github.com/blockcypher/gobcy/v2"
)

func TxBTC(btcAPI gobcy.API, from, to string, amount int64) (*gobcy.TXSkel, error) {
	tx, err := btcAPI.NewTX(gobcy.TempNewTX(from, to, *big.NewInt(amount)), true)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func HashBTC(tx *gobcy.TXSkel) ([]byte, error) {
	return hex.DecodeString(tx.ToSign[0])
}

func SendBTC() {

}

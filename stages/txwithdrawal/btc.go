package txwithdrawal

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TxBTC() (*wire.MsgTx, error) {
	// create tx
	tx := wire.NewMsgTx(wire.TxVersion)
	// create input
	prevOutHash, err := hex.DecodeString("f5d8ee39a430901c91a5917b9f2dc19d6d1a0e9cea205b009ca73dd04470b9a6")
	if err != nil {
		return nil, err
	}
	chainHash, err := chainhash.NewHash(prevOutHash)
	if err != nil {
		return nil, err
	}
	prevOutPoint := wire.NewOutPoint(chainHash, 0xffffffff)
	prevOut := wire.NewTxIn(prevOutPoint, nil, nil)
	tx.AddTxIn(prevOut)
	
	// create output
	// pkScript, err := hex.DecodeString("76a9148bbc3c1f4a2a3c8e6d091c8ebd0c3e2c4c7d66488ac")
	// if err != nil {
	// 	return nil, err
	// }
	// scriptPubKey, err := txscript.NewScriptBuilder().AddData(pkScript).Script()
	// if err != nil {
	// 	return nil, err
	// }
	addr, _ := btcutil.NewAddressPubKeyHash([]byte("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX"), &chaincfg.MainNetParams)
	pkScriptAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	tx.AddTxOut(wire.NewTxOut(100000000, pkScriptAddr))

	return tx, nil
}

func HashBTC() ([]byte, error) {
	return nil, nil
}

// Добавление выхода транзакции
// 	pkScript, _ := hex.DecodeString("76a9148bbc3c1f4a2a3c8e6d091c8ebd0c3e2c4c7d66488ac")
// 	scriptPubKey, err := txscript.NewScriptBuilder().AddData(pkScript).Script()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	pkScriptAddr, err := txscript.PayToAddrScript("1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX", &chaincfg.MainNetParams)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	tx.AddTxOut(wire.NewTxOut(100000000, pkScriptAddr))

// Подпись транзакции
// 	privKeyBytes, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
// 	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
// 	sigScript, err := txscript.SignatureScript(tx, 0, pkScript, txscript.SigHashAll, privKey, false)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	tx.TxIn[0].SignatureScript = sigScript

// 	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
// 	tx.Serialize(buf)

// 	fmt.Printf("Transaction: %x\n", buf.Bytes())
// }

// https://blockchain.info/rawaddr/{bitcoin_address}
// Замените {bitcoin_address} на свой адрес Bitcoin.
// Этот запрос вернет список всех транзакций, связанных с вашим адресом, в формате JSON.

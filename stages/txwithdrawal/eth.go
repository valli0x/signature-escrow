package txwithdrawal

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TxETH(client *ethclient.Client, from string, to string, amount, gasLimit, chain int64) (*types.Transaction, []byte, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, nil, err
	}
	chainID.SetInt64(chain)

	nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(from))
	if err != nil {
		return nil, nil, err
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, nil, err
	}
	tx := types.NewTransaction(nonce, common.HexToAddress(to), big.NewInt(amount), uint64(gasLimit), gasPrice, []byte{})
	hash := types.NewLondonSigner(chainID.SetInt64(chain)).Hash(tx).Bytes()

	return tx, hash, nil
}

func HashETH(client *ethclient.Client, tx *types.Transaction, chain int64) ([]byte, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	return types.NewLondonSigner(chainID.SetInt64(chain)).Hash(tx).Bytes(), nil
}

func WithSignatureETH(client *ethclient.Client, tx *types.Transaction, sig []byte, chain int64) (*types.Transaction, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	chainID.SetInt64(chain)

	return tx.WithSignature(types.NewLondonSigner(chainID), sig)
}

func SendTxETH(client *ethclient.Client, signedTx *types.Transaction) error {
	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}
	return nil
}

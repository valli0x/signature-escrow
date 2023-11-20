package txwithdrawal

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TxETH(client *ethclient.Client, from string, to string, amount, gasLimit int64) (*types.Transaction, error) {
	nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(from))
	if err != nil {
		return nil, err
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, err
	}

	return types.NewTransaction(
		nonce,
		common.HexToAddress(to),
		big.NewInt(amount),
		uint64(gasLimit),
		gasPrice,
		[]byte{}), nil
}

func HashETH(client *ethclient.Client, tx *types.Transaction, chain int64) ([]byte, error) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	return types.NewLondonSigner(chainID.SetInt64(chain)).Hash(tx).Bytes(), nil
}

func SendEthTx(client *ethclient.Client, signedTx *types.Transaction) (string, error) {
	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", err
	}

	return signedTx.Hash().String(), nil
}

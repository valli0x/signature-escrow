package checker

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func RefillETH(ctx context.Context, client *ethclient.Client, addr common.Address, expected int64) (bool, error) {
	for {
		balance, err := client.BalanceAt(ctx, addr, nil)
		if err != nil {
			return false, err
		}
		if balance.Int64() == expected {
			return true, nil
		}

		time.Sleep(time.Second * 12) // block is created every 12 seconds in Ethereum
	}
}

func RefillBTC(ctx context.Context, client *rpcclient.Client, addr btcutil.Address, expected int64) (bool, error) {
	for {
		balance, err := client.GetBalanceMinConf(addr.String(), 1)
		if err != nil {
			return false, err
		}
		if balance == btcutil.Amount(expected) {
			return true, nil
		}

		time.Sleep(time.Minute * 10) // block is created every 10 minuts in Bitcoin
	}
}

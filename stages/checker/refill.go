package checker

import (
	"context"
	"time"

	"github.com/blockcypher/gobcy/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func RefillETH(ctx context.Context, client *ethclient.Client, addr common.Address, expected int64) error {
	for {
		balance, err := client.BalanceAt(ctx, addr, nil)
		if err != nil {
			return err
		}
		if balance.Int64() >= expected {
			return nil
		}

		time.Sleep(time.Second * 12) // block is created every 12 seconds in Ethereum
	}
}

func RefillBTC(ctx context.Context, btcAPI gobcy.API, addr btcutil.Address, expected int64) error {
	for {
		wallet, err := btcAPI.GetAddrBal(addr.String(), nil)
		if err != nil {
			return err
		}
		if wallet.Balance.Int64() >= expected {
			return err
		}

		time.Sleep(time.Minute * 10) // block is created every 10 minuts in Bitcoin
	}
}

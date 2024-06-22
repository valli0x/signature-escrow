package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

func WithdrawalTokensETH() *cobra.Command {
	var (
		node string
	)

	cmd := &cobra.Command{
		Use:   "eth-tx-hash",
		Short: "Create and print the hash of an Ethereum transaction",
		Long: `This command connects to an Ethereum node via RPC,
	fetches the current nonce for a given account,
	creates a new transaction with specified fields,
	and then prints the hash of this transaction.
	It uses go-ethereum library for Ethereum interaction.
	Usage: eth-tx-hash <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value>`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) < 6 {
				fmt.Println("Usage: eth-tx-hash <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value> <Signature>")
				return
			}

			from := common.HexToAddress(args[0])
			to := common.HexToAddress(args[3])
			sig := args[5]
			gasPrice, _ := strconv.ParseUint(args[1], 10, 32)
			gasLimit, _ := strconv.ParseUint(args[2], 10, 32)
			value, _ := strconv.ParseUint(args[4], 10, 64)

			// Convert uint64 values to *big.Int
			// TODO
			gasPriceBigInt := big.NewInt(int64(gasPrice))
			valueBigInt := big.NewInt(int64(value))

			// Connect to Ethereum node
			client, err := ethclient.Dial(node)
			if err != nil {
				return err
			}

			nonce, err := client.NonceAt(context.Background(), from, nil)
			if err != nil {
				return err
			}

			// Create a new transaction
			tx := types.NewTransaction(
				nonce+1,
				to,
				valueBigInt,
				gasLimit,
				gasPriceBigInt,
				nil)

			// signature byte format
			sigB, err := hex.DecodeString(sig)
			if err != nil {
				return err
			}

			// chain ID
			chainID, err := client.NetworkID(context.Background())
			if err != nil {
				return err
			}
			chainID.SetInt64(1) // mainnet

			// set signature to tx
			tx, err = tx.WithSignature(types.NewLondonSigner(chainID), sigB)
			if err != nil {
				return err
			}

			// send tx
			if err := client.SendTransaction(context.Background(), tx); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&node, "node", "", "ethereum node address")

	return nil
}

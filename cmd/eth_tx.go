package cmd

import (
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"
)

type EthTxFlags struct {
	Node string
}

var (
	ethTxFlags = &EthTxFlags{}
)

func init() {
	command := EthTx()
	command.PersistentFlags().StringVar(&ethTxFlags.Node, "node", "", "ethereum node address")
	RootCmd.AddCommand(command)
}

func EthTx() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ethereum-transaction",
		Short: "Create and print the hash of an Ethereum transaction",
		Long: `This command connects to an Ethereum node via RPC,
	fetches the current nonce for a given account,
	creates a new transaction with specified fields,
	and then prints the hash of this transaction.
	It uses go-ethereum library for Ethereum interaction.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 6 {
				fmt.Println("Usage: ethereum-transaction <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value>")
				return
			}

			from := common.HexToAddress(args[0])
			gasPrice, _ := strconv.ParseUint(args[2], 10, 32)
			gasLimit, _ := strconv.ParseUint(args[3], 10, 32)
			value, _ := strconv.ParseUint(args[5], 10, 64)

			// Convert uint64 values to *big.Int
			gasPriceBigInt := big.NewInt(int64(gasPrice))
			valueBigInt := big.NewInt(int64(value))

			// Connect to Ethereum node
			client, err := rpc.Dial(ethTxFlags.Node)
			if err != nil {
				log.Fatalf("Failed to connect to the Ethereum client: %v", err)
			}

			// Get current nonce for the account
			var nonceResult string
			err = client.Call(&nonceResult, "eth_getTransactionCount", from.Hex(), false)
			if err != nil {
				log.Fatalf("Failed to get nonce: %v", err)
			}

			currentNonce, _ := strconv.ParseUint(nonceResult, 10, 64)
			newNonce := currentNonce + 1

			// Create a new transaction
			tx := types.NewTransaction(
				newNonce,
				common.HexToAddress(args[4]),
				valueBigInt,
				gasLimit,
				gasPriceBigInt,
				nil)

			// Calculate the transaction hash
			txHash := tx.Hash()

			fmt.Printf("The hash of the transaction is: %s\n", txHash.Hex())
		},
	}

	return cmd
}

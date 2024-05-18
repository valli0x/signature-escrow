package cmd

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/spf13/cobra"
)

type EthTxFlags struct {
}

var (
	ethTxFlags = &EthTxFlags{}
)

func init() {
	command := EthTx()
	RootCmd.AddCommand(command)
}

func EthTx() *cobra.Command {

	cmd := &cobra.Command{
		Use:          "eth-tx",
		Short:        "Create ethereum withdrawal transaction from escrow",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// tx data
			var (
				nonce    uint64
				to       common.Address
				amount   *big.Int
				gasLimit uint64
				gasPrice *big.Int
				data     []byte
			)

			tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

			fmt.Println("Transaction hash:", tx.Hash().Hex())
			return nil
		},
	}

	return cmd
}

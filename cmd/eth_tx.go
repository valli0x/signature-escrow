package cmd

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

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

			to, err = EthTo()
			if err != nil {
				return err
			}

			tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data)

			fmt.Println("Transaction hash:", tx.Hash().Hex())
			return nil
		},
	}

	return cmd
}

func EthTo() (common.Address, error) {
	fmt.Print("to: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return common.Address{}, err
	}
	input = strings.TrimRight(input, "\n")
	return common.HexToAddress(input), nil
}

func EthAmount() (int64, error) {
	fmt.Print("your value: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return 0, err
	}
	input = strings.TrimRight(input, "\n")
	value, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

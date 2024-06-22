package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/config"
)

var (
	homeDir, storPass string
	rootCmd           *cobra.Command
	env               *config.Env
)

func init() {
	// create main command
	rootCmd = &cobra.Command{
		Use:   "escrow",
		Short: "client and server signature-escrow",
	}
	rootCmd.PersistentFlags().StringVar(&homeDir, "config", "", "Directory for config ")
	rootCmd.PersistentFlags().StringVar(&storPass, "pass", "", "password for storage")

	// loading config
	cobra.OnInitialize(func() {
		env = config.NewConfig()
		if err := env.Load(homeDir); err != nil {
			fmt.Println("init error:", err)
			os.Exit(1)
		}
	})

	// add commands
	rootCmd.AddCommand(
		// Example of creating shared escrow accounts and exchanging signatures
		FullyExchange(),

		// stage 1
		// Forming a common key pair
		Keygen(),

		// stage 2 checking escrow balance

		// stage 3
		// getting the hash of the eth transaction
		EthTxHash(),
		// sending the other party an incomplete hash signature on the withdrawal of their tokens from the escrow account
		SendWithdrawalTx(),
		// obtaining an incomplete signature of the transaction hash to withdraw funds from another participant
		// and obtaining a full signature
		AcceptWithdrawalTx(),

		// stage 4
		// starting a signature exchange server
		StartEscrowServer(),
		// exchange of signatures via an escrow server
		ExchangeSignature(),

		// sending an eth transaction to the network
		WithdrawalTokensETH(),
	)
}

func Start() error {
	return rootCmd.Execute()
}

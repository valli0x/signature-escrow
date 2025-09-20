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

	rootCmd.AddCommand(
		StartKeyServer(),
		StartEscrowServer(),
		ExchangeSignature(),
	)
}

func Start() error {
	return rootCmd.Execute()
}

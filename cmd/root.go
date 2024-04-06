package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/config"
)

var (
	homeDir     string
	storagePass string
	env         *config.Env
)

var RootCmd = &cobra.Command{
	Use:   "escrow",
	Short: "client and server signature-escrow",
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&homeDir, "config", "", "Directory for config ")
	RootCmd.PersistentFlags().StringVar(&storagePass, "pass", "", "password for storage")
}

func initConfig() {
	env = config.NewConfig()

	if err := env.Load(homeDir); err != nil {
		fmt.Println("init error:", err)
		os.Exit(1)
	}
}

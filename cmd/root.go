package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/config"
)

var (
	homeDir       string
	RuntimeConfig *config.RuntimeConfig
)

var RootCmd = &cobra.Command{
	Use:   "escrow",
	Short: "client and server signature-escrow",
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&homeDir, "config", "", "Directory for config ")
}

func initConfig() {
	RuntimeConfig = config.NewConfig()
	handleInitError(RuntimeConfig.Load(homeDir))
}

func handleInitError(err error) {
	if err != nil {
		fmt.Println("init error:", err)
		os.Exit(1)
	}
}

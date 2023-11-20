package cmd

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/stages/escrowbox"
	"github.com/valli0x/signature-escrow/storage"
)

type ServerFlags struct {
	Port     string
	Password string
}

var (
	serverFlags = &ServerFlags{}
)

func init() {
	command := StartServer()
	command.PersistentFlags().StringVar(&serverFlags.Port, "port", ":8282", "servers port")
	command.PersistentFlags().StringVar(&serverFlags.Password, "pass", "", "password for storage")

	RootCmd.AddCommand(command)
}

func StartServer() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Escrow agent",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
				Name:   "server command",
				Output: os.Stdout,
				Level:  hclog.DefaultLevel,
			})

			logger.Info("create storage...")
			stor, err := storage.CreateBackend(
				"server",
				RuntimeConfig.StorageType, serverFlags.Password, RuntimeConfig.StorageConfig,
				logger.Named("storage"))
			if err != nil {
				return err
			}

			logger.Info("run server on port " + serverFlags.Port)
			if err := escrowbox.NewServer(serverFlags.Port, stor).Start(); err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}

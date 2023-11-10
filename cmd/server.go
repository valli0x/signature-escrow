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
	serverStart := StartServer()
	serverStart.PersistentFlags().StringVar(&serverFlags.Port, "port", ":8080", "servers port")
	serverStart.PersistentFlags().StringVar(&serverFlags.Port, "pass", "", "password for storage")

	RootCmd.AddCommand(serverStart)
}

func StartServer() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Escrow agent",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// create logger
			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
				Name:   "server command",
				Output: os.Stdout,
				Level:  hclog.DefaultLevel,
			})

			logger.Info("create storage...")
			storType := RuntimeConfig.StorageType
			storConf := RuntimeConfig.StorageConfig
			stor, err := storage.CreateBackend("server", storType, serverFlags.Password, storConf, logger.Named("storage"))
			if err != nil {
				return err
			}

			logger.Info("storage server...")
			server := escrowbox.NewServer(serverFlags.Port, stor)
			if err := server.Start(); err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}

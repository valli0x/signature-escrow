package cmd

import (
	"context"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/stages/escrowbox"
	"github.com/valli0x/signature-escrow/storage"
)

type ServerFlags struct {
	Addr string
}

var (
	serverFlags = &ServerFlags{}
)

func init() {
	command := StartServer()
	command.PersistentFlags().StringVar(&serverFlags.Addr, "address", "localhost:8282", "server address")

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
				env.StorageType, storagePass, env.StorageConfig,
				logger.Named("storage"))
			if err != nil {
				return err
			}

			logger.Info("configuration server")
			server := escrowbox.NewServer(&escrowbox.SrvConfig{
				Addr: serverFlags.Addr,
				Stor: stor,
			})

			server.Run(context.Background())
			return nil
		},
	}
	return cmd
}

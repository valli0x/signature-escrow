package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/keyserver"
	"github.com/valli0x/signature-escrow/storage"
)

func StartKeyServer() *cobra.Command {
	var (
		addr string
	)

	cmd := &cobra.Command{
		Use:          "keyserver",
		Short:        "Start key generation server",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
				Name:   "keyserver",
				Output: os.Stdout,
				Level:  hclog.DefaultLevel,
			})

			// Storage setup
			logger.Trace("create storage...")
			pass, storconf := storPass, env.StorageConfig

			fileStor, err := storage.NewFileStorage(storconf, logger.Named("storage"))
			if err != nil {
				return err
			}
			stor, err := storage.NewEncryptedStorage(fileStor, pass)
			if err != nil {
				return err
			}

			// Server configuration
			config := &keyserver.ServerConfig{
				Addr:   addr,
				Stor:   stor,
				Logger: logger,
				Env:    env,
			}

			server := keyserver.NewServer(config)

			// Setup context for graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle signals for graceful shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigChan
				logger.Info("Shutdown signal received")
				cancel()
			}()

			fmt.Printf("Starting key generation server on %s\n", addr)
			server.Run(ctx)

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&addr, "addr", ":8080", "server listen address")

	return cmd
}
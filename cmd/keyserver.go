package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/keyserver"
	"github.com/valli0x/signature-escrow/storage"
	"google.golang.org/grpc"
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
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			// Storage setup
			logger.Debug("create storage...")
			pass, storconf := storPass, env.StorageConfig

			fileStor, err := storage.NewFileStorage(storconf, logger.With("component", "storage"))
			if err != nil {
				return err
			}
			stor, err := storage.NewEncryptedStorage(fileStor, pass)
			if err != nil {
				return err
			}

			// Network setup
			conn, err := grpc.NewClient(addr)
			if err != nil {
				return err
			}

			// Server configuration
			config := &keyserver.ServerConfig{
				Addr:        addr,
				Stor:        stor,
				Logger:      logger,
				Env:         env,
				StoragePass: pass,
				Conn:        conn,
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

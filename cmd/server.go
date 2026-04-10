package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/server"
	"github.com/valli0x/signature-escrow/storage"
)

func StartServer() *cobra.Command {
	var (
		addr      string
		jwtSecret string
	)

	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Start host server (auth, escrow, communication)",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

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

			config := &server.ServerConfig{
				Addr:      addr,
				Stor:      stor,
				Logger:    logger,
				JWTSecret: []byte(jwtSecret),
			}

			srv := server.NewServer(config)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigChan
				logger.Info("Shutdown signal received")
				cancel()
			}()

			fmt.Printf("Starting host server on %s\n", addr)
			srv.Run(ctx)

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&addr, "addr", ":8282", "server listen address")
	cmd.PersistentFlags().StringVar(&jwtSecret, "jwt-secret", "", "secret key for JWT token signing")

	return cmd
}

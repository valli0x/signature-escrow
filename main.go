package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/valli0x/signature-escrow/client"
	"github.com/valli0x/signature-escrow/config"
	"github.com/valli0x/signature-escrow/network"
	"github.com/valli0x/signature-escrow/server"
	"github.com/valli0x/signature-escrow/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	_ = godotenv.Load()
	env := config.LoadFromEnv()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("shutdown signal received")
		cancel()
	}()

	var err error
	switch env.Mode {
	case "server":
		err = runServer(ctx, env, logger)
	case "client":
		err = runClient(ctx, env, logger)
	case "communication":
		err = runCommunication(env, logger)
	default:
		err = fmt.Errorf("unknown MODE: %s (expected: server, client, communication)", env.Mode)
	}

	if err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func runServer(ctx context.Context, env *config.Env, logger *slog.Logger) error {
	stor, err := makeStorage(env, logger)
	if err != nil {
		return err
	}

	srv := server.NewServer(&server.ServerConfig{
		Addr:      env.ServerAddr,
		Stor:      stor,
		Logger:    logger,
		JWTSecret: []byte(env.JWTSecret),
	})

	logger.Info("starting host server", "addr", env.ServerAddr)
	srv.Run(ctx)
	return nil
}

func runClient(ctx context.Context, env *config.Env, logger *slog.Logger) error {
	stor, err := makeStorage(env, logger)
	if err != nil {
		return err
	}

	var commCreds credentials.TransportCredentials = insecure.NewCredentials()
	if os.Getenv("COMMUNICATION_TLS") == "true" || os.Getenv("COMMUNICATION_TLS") == "1" {
		commCreds = credentials.NewTLS(&tls.Config{})
	}
	conn, err := grpc.NewClient(env.Communication, grpc.WithTransportCredentials(commCreds))
	if err != nil {
		return fmt.Errorf("grpc connect: %w", err)
	}

	c := client.NewClient(&client.ClientConfig{
		Addr:        env.ClientAddr,
		Stor:        stor,
		Logger:      logger,
		Env:         env,
		StoragePass: env.StoragePass,
		Conn:        conn,
		JWTSecret:   env.JWTSecret,
		ClientAuth:  env.ClientAuth,
	})

	logger.Info("starting client server", "addr", env.ClientAddr)
	c.Run(ctx)
	return nil
}

func runCommunication(env *config.Env, logger *slog.Logger) error {
	srv, err := network.NewServer(env.Communication, env.NatsURL)
	if err != nil {
		return fmt.Errorf("communication server: %w", err)
	}

	logger.Info("starting communication server", "addr", env.Communication, "nats", env.NatsURL)
	return srv.Run()
}

func makeStorage(env *config.Env, logger *slog.Logger) (storage.Storage, error) {
	storConf := map[string]string{"path": env.StoragePath}

	fileStor, err := storage.NewFileStorage(storConf, logger.With("component", "storage"))
	if err != nil {
		return nil, fmt.Errorf("file storage: %w", err)
	}

	if env.StoragePass == "" {
		return fileStor, nil
	}

	encStor, err := storage.NewEncryptedStorage(fileStor, env.StoragePass)
	if err != nil {
		return nil, fmt.Errorf("encrypted storage: %w", err)
	}
	return encStor, nil
}

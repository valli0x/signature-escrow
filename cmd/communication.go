package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/network"
)

func StartCommunicationServer() *cobra.Command {
	var (
		port    string
		natsurl string
	)

	cmd := &cobra.Command{
		Use:          "communication",
		Short:        "Start communication gRPC server",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, err := network.NewServer(port, natsurl)
			if err != nil {
				return fmt.Errorf("failed to create communication server: %w", err)
			}

			fmt.Printf("Starting communication server on %s (NATS: %s)\n", port, natsurl)
			return srv.Run()
		},
	}

	cmd.PersistentFlags().StringVar(&port, "port", ":6379", "gRPC listen port")
	cmd.PersistentFlags().StringVar(&natsurl, "nats", "nats://localhost:4222", "NATS server URL")

	return cmd
}

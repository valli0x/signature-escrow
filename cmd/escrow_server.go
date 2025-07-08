package cmd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/spf13/cobra"
	"github.com/valli0x/signature-escrow/stages/escrowbox"
	"github.com/valli0x/signature-escrow/storage"
)

// Command for starting escrow server.
// Escrow server checks signature from participant
func StartEscrowServer() *cobra.Command {
	var (
		address string
	)

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
			fileStor, err := storage.NewFileStorage(env.StorageConfig, logger.Named("storage"))
			if err != nil {
				return err
			}
			stor, err := storage.NewEncryptedStorage(fileStor, storPass)
			if err != nil {
				return err
			}

			logger.Info("configuration server")
			server := escrowbox.NewServer(&escrowbox.SrvConfig{
				Addr: address,
				Stor: stor,
			})

			server.Run(context.Background())
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&address, "address", "localhost:8282", "server address")

	return cmd
}

func ExchangeSignature() *cobra.Command {
	var (
		alg string
	)
	cmd := &cobra.Command{
		Use:          "get-signature",
		Short:        "Exchange signature",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) < 3 {
				fmt.Println("Usage: get-signature <another signature> <own pub> <own hash of withdrawal tx>")
				return
			}

			// ids setup
			myid, err := uuid.GenerateUUID()
			if err != nil {
				return err
			}
			myid = strings.ReplaceAll(myid, "-", "")[:32]
			fmt.Printf("your ID: %s\n", myid)

			// another of participant ID
			another, err := readID()
			if err != nil {
				return err
			}
			another = strings.ReplaceAll(another, "-", "")[:32]

			idExchange := getid(myid, another)

			signature := args[0]
			pubkey := args[1]
			hash := args[2]

			switch alg {
			case "ecdsa":
				postData := map[string]string{
					"alg":  "ecdsa",
					"id":   idExchange,
					"pub":  pubkey,
					"hash": hash,
					"sig":  signature,
				}

				for {
					mysig, err := PostEscrow(env.EscrowServer, postData)
					if err != nil {
						return err
					}
					if mysig != nil {
						fmt.Println("my signature of withdrawal tx:", hex.EncodeToString(mysig))
						break
					}
					postData["sig"] = ""

					time.Sleep(time.Second * 5)
				}

			case "frost":

			default:
				return errors.New("unknown alg(frost or ecdsa)")

			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&alg, "alg", "", "escrow alg type(frost or ecdsa)")
	return cmd
}

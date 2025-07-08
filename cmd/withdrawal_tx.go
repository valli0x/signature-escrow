package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/storage"
)

// Command send the own withdrawal transaction with our incomplete signature
func SendWithdrawalTx() *cobra.Command {
	var (
		alg, name string
	)

	cmd := &cobra.Command{
		Use:          "send-withdrawal-tx",
		Short:        "Send withdrawal transaction",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) < 2 {
				fmt.Println("Usage: send-withdrawal-tx <escrow account> <hash of tx>")
				return
			}

			escrowAddress := args[0]
			hashTxWithdrawal := args[1]

			// setup
			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
				Name:   "client command",
				Output: os.Stdout,
				Level:  hclog.DefaultLevel,
			})

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

			// network setup
			logger.Trace("network setup")
			net, err := redis.NewRedisNet(env.Communication, myid, another, logger.Named("network"))
			if err != nil {
				return err
			}

			print(stor, net)

			// send incomplete signature
			switch alg {
			case "ecdsa":
				// getting config and presign
				config := mpccmp.EmptyConfig()
				data, err := stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(data, config); err != nil {
					return err
				}

				presign := mpccmp.EmptyPreSign()
				data, err = stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(data, presign); err != nil {
					return err
				}

				// getting incomplete signature our withrawal transaction
				pl := pool.NewPool(0)
				defer pl.TearDown()

				hashB, err := hex.DecodeString(hashTxWithdrawal)
				if err != nil {
					return err
				}

				incsig, err := mpccmp.CMPPreSignOnlineInc(config, presign, hashB, pl)
				if err != nil {
					return err
				}

				incsigHex, err := mpccmp.MsgToHex(incsig)
				if err != nil {
					return err
				}

				tx := struct {
					IncSig string `json:"inc_sig"`
					HashTx string `json:"hash_tx"`
				}{
					IncSig: incsigHex,
					HashTx: hashTxWithdrawal,
				}

				// send incsig and hash of the withdrawal transaction
				msg := &protocol.Message{}
				msg.Data, err = json.Marshal(tx)
				if err != nil {
					return err
				}
				net.Send(msg)

			case "frost":
				// TODO:
			default:
				return errors.New("unknown alg(frost or ecdsa)")
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&alg, "alg", "", "escrow alg type(frost or ecdsa)")
	cmd.PersistentFlags().StringVar(&name, "name", "", "name for key pair")
	return cmd
}

// Command accept the own withdrawal transaction with our incomplete signature
func AcceptWithdrawalTx() *cobra.Command {
	var (
		alg, name string
	)

	cmd := &cobra.Command{
		Use:          "accept-withdrawal-tx",
		Short:        "Accept another withdrawal transaction",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) < 2 {
				fmt.Println("Usage: accept-withdrawal-tx <escrow account>")
				return
			}

			// escrow address
			address := args[0]

			// setup
			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
				Name:   "client command",
				Output: os.Stdout,
				Level:  hclog.DefaultLevel,
			})

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

			// network setup
			logger.Trace("network setup")
			net, err := redis.NewRedisNet(env.Communication, myid, another, logger.Named("network"))
			if err != nil {
				return err
			}

			// accept incomplete signature and sign it
			switch alg {
			case "ecdsa":
				msg := <-net.Next()

				tx := struct {
					IncSig string `json:"inc_sig"`
					HashTx string `json:"hash_tx"`
				}{}

				if err := json.Unmarshal(msg.Data, &tx); err != nil {
					return err
				}

				// getting config and presign
				config := mpccmp.EmptyConfig()
				data, err := stor.Get(context.Background(), name+"/"+address+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(data, config); err != nil {
					return err
				}

				presign := mpccmp.EmptyPreSign()
				data, err = stor.Get(context.Background(), name+"/"+address+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(data, presign); err != nil {
					return err
				}

				// getting another complete signature of the withdrawal transaction
				hashB, err := hex.DecodeString(tx.HashTx)
				if err != nil {
					return err
				}

				incsig, err := mpccmp.HexToMsg(tx.IncSig)
				if err != nil {
					return err
				}

				pl := pool.NewPool(0)
				defer pl.TearDown()

				sig, err := mpccmp.CMPPreSignOnlineCoSign(config, presign, hashB, incsig, pl)
				if err != nil {
					return err
				}

				sigEthereum, err := mpccmp.GetSigByte(sig)
				if err != nil {
					return err
				}

				fmt.Printf("Another complete signature of the withdrawal transaction:%s",
					hex.EncodeToString(sigEthereum))

			case "frost":
				msg := <-net.Next()
				println(msg)
				// TODO:

			default:
				return errors.New("unknown alg(frost or ecdsa)")
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&alg, "alg", "", "escrow alg type(frost or ecdsa)")
	cmd.PersistentFlags().StringVar(&name, "name", "", "name for key pair")
	return cmd
}

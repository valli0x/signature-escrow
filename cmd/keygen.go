package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/storage"
)

// Command for creating shared Bitcoin or Ethereum keys
func Keygen() *cobra.Command {
	var (
		name, keyType string
	)

	cmd := &cobra.Command{
		Use:          "keygen",
		Short:        "Keygen ECDSA and FROST shared keys",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			/*
				setup
			*/

			if keyType != "ecdsa" && keyType != "frost" {
				return errors.New("unknown alg(ecdsa or frost alg)")
			}

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

			signers := party.IDSlice{party.ID(myid), party.ID(another)}

			// network setup
			logger.Trace("network setup")
			net, err := redis.NewRedisNet(env.Communication, myid, another, logger.Named("network"))
			if err != nil {
				return err
			}

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

			if err := ping(net); err != nil {
				return err
			}

			/*
				start keygen
			*/

			logger.Trace("keygen ecdsa or schnorr")

			switch keyType {
			case "ecdsa":
				space()
				pl := pool.NewPool(0)
				defer pl.TearDown()

				fmt.Println("Keygen ETH...")
				configETH, err := mpccmp.CMPKeygen(party.ID(myid), signers, 1, net, pl)
				if err != nil {
					return err
				}
				presignature, err := mpccmp.CMPPreSign(configETH, signers, net, pl)
				if err != nil {
					return err
				}
				if err := mpccmp.PrintAddressPubKeyECDSA(configETH); err != nil {
					return err
				}
				address, err := mpccmp.GetAddress(configETH)
				if err != nil {
					return err
				}

				fmt.Println("Saving private config")
				kb, err := configETH.MarshalBinary()
				if err != nil {
					return err
				}

				preSignB, err := cbor.Marshal(presignature)
				if err != nil {
					return err
				}

				if err := stor.Put(context.Background(), name+"/"+address+"/conf-ecdsa", kb); err != nil {
					return err
				}

				if err := stor.Put(context.Background(), name+"/"+address+"/presig-ecdsa", preSignB); err != nil {
					return err
				}
				space()
			case "frost":
				space()
				// keygen in BTC network
				fmt.Println("Keygen BTC...")
				configBTC, err := mpcfrost.FrostKeygenTaproot(party.ID(myid), signers, 1, net)
				if err != nil {
					return err
				}
				if err := mpcfrost.PrintAddressPubKeyTaproot(myid, configBTC); err != nil {
					return err
				}
				address, err := mpcfrost.GetAddress(configBTC)
				if err != nil {
					return err
				}

				fmt.Println("Keygen private config")
				configb, err := cbor.Marshal(configBTC)
				if err != nil {
					return err
				}

				if err := stor.Put(context.Background(), name+"/"+address.String()+"/conf-frost", configb); err != nil {
					return err
				}
				space()
			default:
				return errors.New("unknown key type")
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&keyType, "alg", "", "shared keys type(ecdsa or frost)")
	cmd.PersistentFlags().StringVar(&name, "name", "", "name for key pair")

	return cmd
}

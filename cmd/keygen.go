package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/storage"
)

type KeygenFlags struct {
	KeyType string
}

var (
	keygenFlags = &KeygenFlags{}
)

func init() {
	command := Keygen()
	command.PersistentFlags().StringVar(&keygenFlags.KeyType, "alg", "", "shared keys type")
	RootCmd.AddCommand(command)
}

func Keygen() *cobra.Command {

	cmd := &cobra.Command{
		Use:          "keygen",
		Short:        "Keygen ECDSA and FROST shared keys",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			/*
				setup
			*/

			if keygenFlags.KeyType != "ecdsa" && keygenFlags.KeyType != "frost" {
				return errors.New("unknown alg")
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
			net, err := redis.NewRedisNet(env.Network, myid, another, logger.Named("network"))
			if err != nil {
				return err
			}

			logger.Trace("create storage...")
			stortype, pass, storconf := env.StorageType, storagePass, env.StorageConfig

			stor, err := storage.CreateBackend("keygen", stortype, pass, storconf, logger.Named("storage"))
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

			switch keygenFlags.KeyType {
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

				fmt.Println("Saving private config")
				kb, err := configETH.MarshalBinary()
				if err != nil {
					return err
				}

				preSignB, err := cbor.Marshal(presignature)
				if err != nil {
					return err
				}

				if err := stor.Put(context.Background(), &logical.StorageEntry{
					Key:   myid + "/conf-ecdsa",
					Value: kb,
				}); err != nil {
					return err
				}

				if err := stor.Put(context.Background(), &logical.StorageEntry{
					Key:   myid + "/presig-ecdsa",
					Value: preSignB,
				}); err != nil {
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

				fmt.Println("Keygen private config")
				configb, err := cbor.Marshal(configBTC)
				if err != nil {
					return err
				}

				if err := stor.Put(context.Background(), &logical.StorageEntry{
					Key:   myid + "/conf-frost",
					Value: configb,
				}); err != nil {
					return err
				}
				space()
			default:
				return errors.New("unknown key type")
			}

			return nil
		},
	}

	return cmd
}

func readID() (string, error) {
ID:
	fmt.Print("another ID: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	input = strings.TrimRight(input, "\n")
	if len(input) < 32 {
		fmt.Println("min lenth ID is 32")
		goto ID
	}
	return input, nil
}

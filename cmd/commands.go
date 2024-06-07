package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/valli0x/signature-escrow/config"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/escrowbox"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/storage"
)

/*
	commands:
		Keygen
		EthTxHash
		StartEscrowServer
*/

// Command for creating shared Bitcoin or Ethereum keys
func Keygen(env *config.Env, storagePass string) *cobra.Command {
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

				if err := stor.Put(context.Background(), &logical.StorageEntry{
					Key:   name + "/" + address + "/conf-ecdsa",
					Value: kb,
				}); err != nil {
					return err
				}

				if err := stor.Put(context.Background(), &logical.StorageEntry{
					Key:   name + "/" + address + "/presig-ecdsa",
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
				address, err := mpcfrost.GetAddress(configBTC)
				if err != nil {
					return err
				}

				fmt.Println("Keygen private config")
				configb, err := cbor.Marshal(configBTC)
				if err != nil {
					return err
				}

				if err := stor.Put(context.Background(), &logical.StorageEntry{
					Key:   name + "/" + address.String() + "/conf-frost",
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

	cmd.PersistentFlags().StringVar(&keyType, "alg", "", "shared keys type(ecdsa or frost)")
	cmd.PersistentFlags().StringVar(&name, "name", "", "name for key pair")

	return cmd
}

// Command for getting hash from withdrawal ethereum transaction
func EthTxHash() *cobra.Command {
	var (
		node string
	)

	cmd := &cobra.Command{
		Use:   "eth-tx-hash",
		Short: "Create and print the hash of an Ethereum transaction",
		Long: `This command connects to an Ethereum node via RPC,
	fetches the current nonce for a given account,
	creates a new transaction with specified fields,
	and then prints the hash of this transaction.
	It uses go-ethereum library for Ethereum interaction.
	Usage: eth-tx-hash <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value>`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 5 {
				fmt.Println("Usage: eth-tx-hash <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value>")
				return
			}

			from := common.HexToAddress(args[0])
			to := common.HexToAddress(args[3])
			gasPrice, _ := strconv.ParseUint(args[1], 10, 32)
			gasLimit, _ := strconv.ParseUint(args[2], 10, 32)
			value, _ := strconv.ParseUint(args[4], 10, 64)

			// Convert uint64 values to *big.Int
			gasPriceBigInt := big.NewInt(int64(gasPrice))
			valueBigInt := big.NewInt(int64(value))

			// Connect to Ethereum node
			client, err := rpc.Dial(node)
			if err != nil {
				log.Fatalf("Failed to connect to the Ethereum client: %v", err)
			}

			// Get current nonce for the account
			var result string
			err = client.Call(&result, "eth_getTransactionCount", from.Hex(), "latest")
			if err != nil {
				log.Fatalf("Failed to get nonce: %v", err)
			}

			currentNonce, _ := strconv.ParseUint(result, 10, 64)

			// Create a new transaction
			tx := types.NewTransaction(
				currentNonce+1,
				to,
				valueBigInt,
				gasLimit,
				gasPriceBigInt,
				nil)

			// Calculate the transaction hash
			txHash := tx.Hash()

			space()

			fmt.Printf("The hash of the tx is: %s\n", txHash.Hex())
		},
	}

	cmd.PersistentFlags().StringVar(&node, "node", "", "ethereum node address")

	return cmd
}

// Command send the own withdrawal transaction with our incomplete signature
func SendWithdrawalTx(env *config.Env, storagePass string) *cobra.Command {
	var (
		alg string
	)

	cmd := &cobra.Command{
		Use:          "send-withdrawal-tx",
		Short:        "Send withdrawal transaction",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
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
			stortype, pass, storconf := env.StorageType, storagePass, env.StorageConfig

			stor, err := storage.CreateBackend("keygen", stortype, pass, storconf, logger.Named("storage"))
			if err != nil {
				return err
			}

			// network setup
			logger.Trace("network setup")
			net, err := redis.NewRedisNet(env.Network, myid, another, logger.Named("network"))
			if err != nil {
				return err
			}

			print(stor, net)

			// send incomplete signature
			switch alg {
			case "ecdsa":

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

// Command accept the own withdrawal transaction with our incomplete signature
func AcceptWithdrawalTx(env *config.Env, storagePass string) *cobra.Command {
	var (
		alg, name string
	)

	cmd := &cobra.Command{
		Use:          "accept-withdrawal-tx",
		Short:        "Accept another withdrawal transaction",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
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

			// network setup
			logger.Trace("network setup")
			net, err := redis.NewRedisNet(env.Network, myid, another, logger.Named("network"))
			if err != nil {
				return err
			}

			// accept incomplete signature and sign it
			switch alg {
			case "ecdsa":
				msg := <- net.Next()
				println(msg)
			case "frost":
				msg := <- net.Next()
				println(msg)
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

// Command for starting escrow server.
// Escrow server checks signature from participant
func StartEscrowServer(env *config.Env, storagePass string) *cobra.Command {
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
			stor, err := storage.CreateBackend(
				"server",
				env.StorageType, storagePass, env.StorageConfig,
				logger.Named("storage"))
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

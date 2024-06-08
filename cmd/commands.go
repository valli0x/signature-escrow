package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/escrowbox"
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
			stortype, pass, storconf := env.StorageType, storPass, env.StorageConfig

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
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) < 5 {
				fmt.Println("Usage: eth-tx-hash <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value>")
				return nil
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
			client, err := ethclient.Dial(node)
			if err != nil {
				return err
			}

			nonce, err := client.NonceAt(context.Background(), from, nil)
			if err != nil {
				return err
			}

			// Create a new transaction
			tx := types.NewTransaction(
				nonce+1,
				to,
				valueBigInt,
				gasLimit,
				gasPriceBigInt,
				nil)

			// Calculate the transaction hash
			txHash := tx.Hash()

			space()

			fmt.Printf("The hash of the tx is: %s\n", txHash.Hex())

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&node, "node", "", "ethereum node address")

	return cmd
}

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
			stortype, pass, storconf := env.StorageType, storPass, env.StorageConfig

			stor, err := storage.CreateBackend("keygen", stortype, pass, storconf, logger.Named("storage"))
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
				entry, err := stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(entry.Value, config); err != nil {
					return err
				}

				presign := mpccmp.EmptyPreSign()
				entry, err = stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(entry.Value, presign); err != nil {
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
			stortype, pass, storconf := env.StorageType, storPass, env.StorageConfig

			stor, err := storage.CreateBackend("keygen", stortype, pass, storconf, logger.Named("storage"))
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
				entry, err := stor.Get(context.Background(), name+"/"+address+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(entry.Value, config); err != nil {
					return err
				}

				presign := mpccmp.EmptyPreSign()
				entry, err = stor.Get(context.Background(), name+"/"+address+"/conf-ecdsa")
				if err != nil {
					return err
				}
				if err := cbor.Unmarshal(entry.Value, presign); err != nil {
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

func WithdrawalTokens() *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) < 6 {
				fmt.Println("Usage: eth-tx-hash <AccountAddress> <GasPrice> <GasLimit> <ToAddress> <Value> <Signature>")
				return
			}

			from := common.HexToAddress(args[0])
			to := common.HexToAddress(args[3])
			sig := args[5]
			gasPrice, _ := strconv.ParseUint(args[1], 10, 32)
			gasLimit, _ := strconv.ParseUint(args[2], 10, 32)
			value, _ := strconv.ParseUint(args[4], 10, 64)

			// Convert uint64 values to *big.Int
			// TODO
			gasPriceBigInt := big.NewInt(int64(gasPrice))
			valueBigInt := big.NewInt(int64(value))

			// Connect to Ethereum node
			client, err := ethclient.Dial(node)
			if err != nil {
				return err
			}

			nonce, err := client.NonceAt(context.Background(), from, nil)
			if err != nil {
				return err
			}

			// Create a new transaction
			tx := types.NewTransaction(
				nonce+1,
				to,
				valueBigInt,
				gasLimit,
				gasPriceBigInt,
				nil)

			// signature byte format
			sigB, err := hex.DecodeString(sig)
			if err != nil {
				return err
			}

			// chain ID
			chainID, err := client.NetworkID(context.Background())
			if err != nil {
				return err
			}
			chainID.SetInt64(1) // mainnet

			// set signature to tx
			tx, err = tx.WithSignature(types.NewLondonSigner(chainID), sigB)
			if err != nil {
				return err
			}

			// send tx
			if err := client.SendTransaction(context.Background(), tx); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&node, "node", "", "ethereum node address")

	return nil
}

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
			stor, err := storage.CreateBackend(
				"server",
				env.StorageType, storPass, env.StorageConfig,
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

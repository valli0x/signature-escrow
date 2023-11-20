package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/escrowbox"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/stages/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/stages/txwithdrawal"
	"github.com/valli0x/signature-escrow/validation"
)

func init() {
	command := Client()
	RootCmd.AddCommand(command)
}

func Client() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "exchange",
		Short:        "Exchange BTC and ETH",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			/*
				setup
			*/
			// setup client
			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
				Name:   "client command",
				Output: os.Stdout,
				Level:  hclog.DefaultLevel,
			})

			// my ID
			my, err := uuid.GenerateUUID()
			if err != nil {
				return err
			}
			my = strings.ReplaceAll(my, "-", "")[:32]
			fmt.Printf("your ID: %s\n", my)

			// another of participant ID
			another, err := readID()
			if err != nil {
				return err
			}
			another = strings.ReplaceAll(another, "-", "")[:32]

			signers := party.IDSlice{party.ID(my), party.ID(another)}

			tokenType, err := readTokenType()
			if err != nil {
				return err
			}
			to, err := readAddress()
			if err != nil {
				return err
			}
			value, err := readValue()
			if err != nil {
				return err
			}

			logger.Trace("network setup")
			net, err := redis.NewRedisNet(RuntimeConfig.Network, my, another, logger.Named("network"))
			if err != nil {
				return err
			}

			if err := ping(net); err != nil {
				return err
			}
			space()

			/*
				stage 1
			*/
			logger.Trace("keygen ETH and BTC")

			// keygen in ETH network
			pl := pool.NewPool(0)
			defer pl.TearDown()

			fmt.Println("Keygen ETH...")
			configETH, err := mpccmp.CMPKeygen(party.ID(my), signers, 1, net, pl)
			if err != nil {
				return err
			}
			presignature, err := mpccmp.CMPPreSign(configETH, signers, net, pl)
			if err != nil {
				return err
			}
			if err := mpccmp.PrintAddressPubKeyECDSA(my, configETH); err != nil {
				return err
			}
			pubkeyETH, err := mpccmp.GetPublicKeyByte(configETH)
			if err != nil {
				return err
			}
			addressETH, err := mpccmp.GetAddress(configETH)
			if err != nil {
				return err
			}
			space()

			// keygen in BTC network
			fmt.Println("Keygen BTC...")
			configBTC, err := mpcfrost.FrostKeygenTaproot(party.ID(my), signers, 1, net)
			if err != nil {
				return err
			}
			if err := mpcfrost.PrintAddressPubKeyTaproot(my, configBTC); err != nil {
				return err
			}
			pubkeyBTC, err := mpcfrost.GetPublicKeyByte(configBTC)
			if err != nil {
				return err
			}
			// addressBTC, err := mpcfrost.GetAddress(configBTC)
			// if err != nil {
			// 	return err
			// }
			space()

			/*
				stage 2
			*/

			fmt.Println("check escrow balance")
			// var btcAPI gobcy.API
			var client *ethclient.Client
			switch tokenType {
			case "BTC":
				// gobcyAPI, err := readGobcyAPI()
				// if err != nil {
				// 	return err
				// }
				// btcAPI = gobcy.API{Token: gobcyAPI, Coin: "btc", Chain: "main"}
				// err = checker.RefillBTC(context.Background(), btcAPI, addressBTC, value)
				// if err != nil {
				// 	return err
				// }
			case "ETH":
				ethAPI, err := readETHAPI()
				if err != nil {
					return err
				}
				client, err = ethclient.Dial(ethAPI)
				if err != nil {
					return err
				}
				// err = checker.RefillETH(context.Background(), client, common.HexToAddress(addressETH), value)
				// if err != nil {
				// 	return err
				// }
			}
			space()

			/*
				stage 3
			*/

			fmt.Println("exchange tx withdrawal")
			mywish := &txwithdrawal.TxWithdrawal{}
			switch tokenType {
			case "BTC":
				// txBTC, err := txwithdrawal.TxBTC(btcAPI, addressBTC.String(), to, value)
				// if err != nil {
				// 	return err
				// }
				// hashBTC, err := txwithdrawal.HashBTC(txBTC)
				// if err != nil {
				// 	return err
				// }
				hash := "cb743e02db612e6e9f15360d3f46e68e8633b98137ae1e17f5d568cd199b450c"
				hashBTC, err := hex.DecodeString(hash)
				if err != nil {
					return err
				}
				hashBTCstr := base64.StdEncoding.EncodeToString(hashBTC)

				// incsig, err := mpcfrost.FrostSignTaprootInc1(configBTC, party.ID(my), hashBTC, signers, net)
				// if err != nil {
				// 	return err
				// }

				// incsigB, err := incsig.MarshalBinary()
				// if err != nil {
				// 	return err
				// }

				idpart, err := uuid.GenerateUUID()
				if err != nil {
					return err
				}
				idpart = strings.ReplaceAll(idpart, "-", "")[:16]

				mywish = &txwithdrawal.TxWithdrawal{
					IDPart:    idpart,
					TokenType: tokenType,
					Address:   to,
					Value:     value,
					Hash:      hashBTCstr,
					// IncSig:    base64.StdEncoding.EncodeToString(incsigB),
				}

			case "ETH":
				txETH, err := txwithdrawal.TxETH(client, addressETH, to, value, 21000)
				if err != nil {
					return err
				}
				hashETH, err := txwithdrawal.HashETH(client, txETH, 1)
				if err != nil {
					return err
				}
				hashETHstr := base64.StdEncoding.EncodeToString(hashETH)

				incsig, err := mpccmp.CMPPreSignOnlineInc(configETH, presignature, hashETH, pl)
				if err != nil {
					return err
				}

				incsigB, err := incsig.MarshalBinary()
				if err != nil {
					return err
				}

				idpart, err := uuid.GenerateUUID()
				if err != nil {
					return err
				}
				idpart = strings.ReplaceAll(idpart, "-", "")[:16]

				mywish = &txwithdrawal.TxWithdrawal{
					IDPart:    idpart,
					TokenType: tokenType,
					Address:   to,
					Value:     value,
					Hash:      hashETHstr,
					IncSig:    base64.StdEncoding.EncodeToString(incsigB),
				}
			}

			myTX := &protocol.Message{}
			myTX.Data, err = json.Marshal(mywish)
			if err != nil {
				return err
			}
			net.Send(myTX)

			anotherTX := <-net.Next()
			anotherwish := &txwithdrawal.TxWithdrawal{}
			if err := json.Unmarshal(anotherTX.Data, anotherwish); err != nil {
				return err
			}

			fmt.Printf("token type: %s address: %s value: %d \n",
				anotherwish.TokenType, anotherwish.Address, anotherwish.Value)

			idExchange := getid(mywish.IDPart, anotherwish.IDPart)

			space()

			/*
				stage 4
			*/
			logger.Trace("send incomplete signature to escrow agent and withdrawal tokens")

			incsig := &protocol.Message{}
			incsigB, err := base64.StdEncoding.DecodeString(anotherwish.IncSig)
			if err != nil {
				return err
			}
			if err := incsig.UnmarshalBinary(incsigB); err != nil {
				return err
			}

			anothersig := []byte{}
			switch anotherwish.TokenType {
			case "BTC":
				// complete signature for withdrawal BTC from escrow another participant
				hashB, err := base64.StdEncoding.DecodeString(anotherwish.Hash)
				if err != nil {
					return err
				}
				sig, err := mpcfrost.FrostSignTaprootCoSign(configBTC, incsig, hashB, signers, net)
				if err != nil {
					return err
				}
				anothersig = sig
			case "ETH":
				// handling sign own withdrawal transaction BTC from escrow(taproot need 2 rounds)
				myhashB, err := base64.StdEncoding.DecodeString(mywish.Hash)
				if err != nil {
					return err
				}
				if err := mpcfrost.FrostSignTaprootInc(configBTC, myhashB, signers, net); err != nil {
					return err
				}

				// complete signature for withdrawal ETH from escrow another participant
				hashB, err := base64.StdEncoding.DecodeString(anotherwish.Hash)
				if err != nil {
					return err
				}
				sig, err := mpccmp.CMPPreSignOnlineCoSign(configETH, presignature, hashB, incsig, pl)
				if err != nil {
					return err
				}
				// sigB, err := mpccmp.SigEthereum(sig)
				// if err != nil {
				// 	return err
				// }
				sigB, err := mpccmp.GetSigByte(sig)
				if err != nil {
					return err
				}
				anothersig = sigB
			}

			fmt.Printf("another signature: %s len: %d\n", hex.EncodeToString(anothersig), len(anothersig)) // !

			// post request to escrow agent
			var pubkey string
			switch tokenType {
			case "BTC":
				pubkey = base64.StdEncoding.EncodeToString(pubkeyBTC)
			case "ETH":
				pubkey = base64.StdEncoding.EncodeToString(pubkeyETH)
			}
			postData := map[string]string{
				"alg":  string(validation.Alg(tokenType)),
				"id":   idExchange,
				"pub":  pubkey,
				"hash": mywish.Hash,
				"sig":  base64.StdEncoding.EncodeToString(anothersig),
			}

			mysig := []byte{}
			for {
				mysig, err = escrowbox.PostEscrow(RuntimeConfig.Escrow, postData)
				if err != nil {
					return err
				}
				if mysig != nil {
					break
				}
				time.Sleep(time.Second * 5)
			}

			fmt.Printf("my signature: %s len %d\n", hex.EncodeToString(mysig), len(mysig)) // !
			return

			// withdrawal transaction
			switch tokenType {
			case "BTC":
				// TODO: send transaction
			case "ETH":
				// TODO: send transaction
			}

			return nil
		},
	}
	return cmd
}

func ping(net network.Network) error {
	fmt.Println("ping...")
	ping := &protocol.Message{
		Data: []byte("ping"),
	}

	for {
		net.Send(ping)
		select {
		case pong := <-net.Next():
			if !bytes.Equal(pong.Data, ping.Data) {
				return errors.New("ping not recieved")
			}
			return nil
		default:
			time.Sleep(time.Second * 5)
		}
	}
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

func space() {
	fmt.Println("---------------------------------------------------")
}

func readTokenType() (string, error) {
TokenType:

	fmt.Print("your token type(BTC or ETH): ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	input = strings.TrimRight(input, "\n")
	if input != "BTC" && input != "ETH" {
		fmt.Println("input incorrect")
		goto TokenType
	}
	return input, nil
}

func readAddress() (string, error) {
	fmt.Print("your address: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	input = strings.TrimRight(input, "\n")
	return input, nil
}

func readValue() (int64, error) {
	fmt.Print("your value: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return 0, err
	}
	input = strings.TrimRight(input, "\n")
	value, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func readGobcyAPI() (string, error) {
	fmt.Print("gobcyAPI: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	input = strings.TrimRight(input, "\n")
	return input, err
}

func readETHAPI() (string, error) {
	fmt.Print("ethereum node url: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	input = strings.TrimRight(input, "\n")
	return input, nil
}

func readCosign() (bool, error) {
	fmt.Print("cosign(yes/no): ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	input = strings.TrimRight(input, "\n")
	return input == "yes", nil
}

func getid(myid, anotherid string) string {
	for i := 0; i < len(myid); i++ {
		if myid[i] == anotherid[i] {
			continue
		}

		if myid[i] > anotherid[i] {
			return myid + anotherid
		} else {
			return anotherid + myid
		}
	}
	return ""
}

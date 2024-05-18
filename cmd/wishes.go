package cmd

// import (
// 	"encoding/base64"
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"os"
// 	"strings"

// 	"github.com/hashicorp/go-hclog"
// 	"github.com/hashicorp/go-uuid"
// 	"github.com/spf13/cobra"
// 	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
// 	"github.com/valli0x/signature-escrow/network/redis"
// 	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
// 	"github.com/valli0x/signature-escrow/stages/txwithdrawal"
// )

// type WishesFlag struct {
// 	Alg string
// }

// var (
// 	wishesFlag = &WishesFlag{}
// )

// func init() {
// 	command := ExchangeWish()
// 	command.PersistentFlags().StringVar(&wishesFlag.Alg, "alg", "", "shared keys type(ecdsa or frost)")
// 	RootCmd.AddCommand(command)
// }

// func ExchangeWish() *cobra.Command {

// 	cmd := &cobra.Command{
// 		Use:          "sign-wishes",
// 		Short:        "Exchange tx withdrawal",
// 		Args:         cobra.ExactArgs(0),
// 		SilenceUsage: true,
// 		RunE: func(cmd *cobra.Command, args []string) (err error) {

// 			if wishesFlag.Alg != "ecdsa" && wishesFlag.Alg != "frost" {
// 				return errors.New("unknown alg(ecdsa or frost alg)")
// 			}

// 			logger := hclog.NewInterceptLogger(&hclog.LoggerOptions{
// 				Name:   "client command",
// 				Output: os.Stdout,
// 				Level:  hclog.DefaultLevel,
// 			})

// 			// ids setup
// 			myid, err := uuid.GenerateUUID()
// 			if err != nil {
// 				return err
// 			}
// 			myid = strings.ReplaceAll(myid, "-", "")[:32]
// 			fmt.Printf("your ID: %s\n", myid)

// 			// another of participant ID
// 			another, err := readID()
// 			if err != nil {
// 				return err
// 			}
// 			another = strings.ReplaceAll(another, "-", "")[:32]

// 			// network setup
// 			logger.Trace("network setup")
// 			net, err := redis.NewRedisNet(env.Network, myid, another, logger.Named("network"))
// 			if err != nil {
// 				return err
// 			}

// 			fmt.Println("exchange tx withdrawal")
// 			mywish := &txwithdrawal.TxWithdrawal{}
// 			switch wishesFlag.Alg {
// 			case "frost":
// 				_, hashBTC, err := txwithdrawal.TxBTC(btcAPI, addressBTC.String(), to, value)
// 				if err != nil {
// 					return err
// 				}

// 				idpart, err := uuid.GenerateUUID()
// 				if err != nil {
// 					return err
// 				}

// 				mywish = &txwithdrawal.TxWithdrawal{
// 					IDPart:    strings.ReplaceAll(idpart, "-", "")[:16],
// 					TokenType: wishesFlag.Alg,
// 					Hash:      base64.StdEncoding.EncodeToString(hashBTC),
// 				}

// 			case "ecdsa":
// 				_, hashETH, err := txwithdrawal.TxETH(client, addressETH, to, value, 21000, 1)
// 				if err != nil {
// 					return err
// 				}

// 				incsig, err := mpccmp.CMPPreSignOnlineInc(configETH, presignature, hashETH, pl)
// 				if err != nil {
// 					return err
// 				}

// 				incsigB, err := incsig.MarshalBinary()
// 				if err != nil {
// 					return err
// 				}

// 				idpart, err := uuid.GenerateUUID()
// 				if err != nil {
// 					return err
// 				}

// 				mywish = &txwithdrawal.TxWithdrawal{
// 					IDPart:    strings.ReplaceAll(idpart, "-", "")[:16],
// 					TokenType: wishesFlag.Alg,
// 					Hash:      base64.StdEncoding.EncodeToString(hashETH),
// 					IncSig:    base64.StdEncoding.EncodeToString(incsigB),
// 				}
// 			}

// 			// send tx withdrawal
// 			myTX := &protocol.Message{}
// 			myTX.Data, err = json.Marshal(mywish)
// 			if err != nil {
// 				return err
// 			}
// 			net.Send(myTX)

// 			// accept my tx withdrawal
// 			anotherTX := <-net.Next()
// 			anotherwish := &txwithdrawal.TxWithdrawal{}
// 			if err := json.Unmarshal(anotherTX.Data, anotherwish); err != nil {
// 				return err
// 			}

// 			idExchange := getid(mywish.IDPart, anotherwish.IDPart)

// 			return nil
// 		},
// 	}

// 	return cmd
// }

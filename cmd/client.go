package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/spf13/cobra"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
)

type ClientFlags struct {
	ID string
}

var (
	clientFlags = &ClientFlags{}
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

			net, err := redis.NewRedisNet(RuntimeConfig.URL, my, another, logger.Named("network"))
			if err != nil {
				return err
			}

			if err := ping(net); err != nil {
				return err
			}
			space()

			// keygen in ETH network
			pl := pool.NewPool(0)
			defer pl.TearDown()

			fmt.Println("Keygen ETH...")
			configETH, err := mpccmp.CMPKeygen(party.ID(my), party.IDSlice{party.ID(my), party.ID(another)}, 1, net, pl)
			if err != nil {
				return err
			}
			if err := mpccmp.PrintAddressPubKeyECDSA(my, configETH); err != nil {
				return err
			}
			space()

			// keygen in BTC network
			fmt.Println("Keygen BTC...")

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
	fmt.Print("another ID: ")
	reader := bufio.NewReader(os.Stdin)
	id, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(id) < 32 {
		return "", errors.New("min lenth ID is 32")
	}
	return id, nil
}

func space() { 
	fmt.Println("---------------------------------------------------")
}
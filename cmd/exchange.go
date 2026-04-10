package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

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

			myid := strings.ReplaceAll(uuid.New().String(), "-", "")[:32]
			fmt.Printf("your ID: %s\n", myid)

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

func PostEscrow(addr string, postData map[string]string) ([]byte, error) {
	dataJson, err := json.Marshal(postData)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, addr+"/v1/escrow", bytes.NewReader(dataJson))
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	answer := &struct {
		Signature string `json:"signature"`
	}{}
	if err := json.NewDecoder(res.Body).Decode(answer); err != nil && err != io.EOF {
		return nil, err
	}

	if answer.Signature == "" {
		return nil, nil
	}
	sig, err := base64.StdEncoding.DecodeString(answer.Signature)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

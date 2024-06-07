package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network"
)

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

	answer := &answer{}
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

type answer struct {
	Signature string
}

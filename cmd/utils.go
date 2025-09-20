package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

package escrowbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
)

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

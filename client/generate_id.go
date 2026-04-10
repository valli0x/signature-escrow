package client

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type IDGenerateResponse struct {
	MyID    string `json:"my_id"`
	Another string `json:"another_id"`
}

func (c *Client) generateIDs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		myid := strings.ReplaceAll(uuid.New().String(), "-", "")[:32]
		another := strings.ReplaceAll(uuid.New().String(), "-", "")[:32]

		response := &IDGenerateResponse{
			MyID:    myid,
			Another: another,
		}

		respondOk(w, response)
	}
}

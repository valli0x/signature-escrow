package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

// AccountMeta is stored locally per account.
type AccountMeta struct {
	Network   string `json:"network"`
	Index     int    `json:"index"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	PairMyID  string `json:"pair_my_id"`
	PairOther string `json:"pair_other"`
	SessionID string `json:"session_id"`
}

type AccountsListResponse struct {
	Accounts []AccountMeta `json:"accounts"`
}

func (c *Client) listAccounts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		network := r.URL.Query().Get("network")

		// Scan known account indices
		accounts := make([]AccountMeta, 0)

		networks := []string{"eth", "btc"}
		if network != "" {
			networks = []string{network}
		}

		for _, net := range networks {
			for i := 1; i <= 100; i++ {
				key := fmt.Sprintf("accounts/%s/%d/meta", net, i)
				data, err := c.stor.Get(context.Background(), key)
				if err != nil || data == nil {
					break
				}
				var meta AccountMeta
				if err := cbor.Unmarshal(data, &meta); err != nil {
					continue
				}
				accounts = append(accounts, meta)
			}
		}

		respondOk(w, AccountsListResponse{Accounts: accounts})
	}
}

func (c *Client) getAccount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Network string `json:"network"`
			Index   int    `json:"index"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Network == "" || req.Index <= 0 {
			respondError(w, http.StatusBadRequest, fmt.Errorf("network and index are required"))
			return
		}

		key := fmt.Sprintf("accounts/%s/%d/meta", req.Network, req.Index)
		data, err := c.stor.Get(context.Background(), key)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if data == nil {
			respondError(w, http.StatusNotFound, fmt.Errorf("account not found"))
			return
		}

		var meta AccountMeta
		if err := cbor.Unmarshal(data, &meta); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("unmarshal error"))
			return
		}

		respondOk(w, meta)
	}
}

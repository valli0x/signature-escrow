package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

// AccountGetRequest identifies an account by network and index.
type AccountGetRequest struct {
	Network string `json:"network"`
	Index   int    `json:"index"`
}

// AccountDeleteRequest identifies an account to delete; Address echoes the
// stored account address as a safety confirmation.
type AccountDeleteRequest struct {
	Network string `json:"network"`
	Index   int    `json:"index"`
	Address string `json:"address"` // confirmation
}

// listAccounts lists locally stored accounts.
//
// @Summary      List accounts
// @Description  List all locally stored accounts, optionally filtered by network.
// @Tags         accounts
// @Produce      json
// @Param        network  query  string  false  "Filter by network: eth or btc"
// @Success      200      {object}  AccountsListResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /v1/accounts/list [get]
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
					// Skip gaps (e.g. after a deletion) instead of stopping,
					// so later accounts remain visible.
					continue
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

// deleteAccount permanently removes one shared account's key material from
// THIS client's storage. The caller must echo the account address as a
// safety confirmation (it must match the stored meta). This is irreversible —
// without this share the 2-of-2 key can never sign again.
//
// @Summary      Delete account
// @Description  Permanently remove one shared account's key material from this client's storage. The Address field must match the stored account address as a safety confirmation. Irreversible.
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        body  body      AccountDeleteRequest  true  "Account to delete (with address confirmation)"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/accounts/delete [post]
func (c *Client) deleteAccount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AccountDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.Network == "" || req.Index <= 0 {
			respondError(w, http.StatusBadRequest, fmt.Errorf("network and index are required"))
			return
		}

		base := fmt.Sprintf("accounts/%s/%d", req.Network, req.Index)
		metaKey := base + "/meta"

		data, err := c.stor.Get(context.Background(), metaKey)
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

		// Address confirmation guard — prevents deleting the wrong account.
		if req.Address != "" && !strings.EqualFold(req.Address, meta.Address) {
			respondError(w, http.StatusBadRequest,
				fmt.Errorf("address confirmation does not match this account"))
			return
		}

		// Remove all artefacts for the account (best-effort each).
		keys := []string{
			metaKey,
			base + "/conf-ecdsa",
			base + "/presig-ecdsa",
			base + "/conf-frost",
			base + "/presig-frost",
		}
		for _, k := range keys {
			_ = c.stor.Delete(context.Background(), k)
		}

		respondOk(w, map[string]any{"deleted": true, "address": meta.Address})
	}
}

// getAccount returns metadata for a single account.
//
// @Summary      Get account
// @Description  Return metadata for a single locally stored account identified by network and index.
// @Tags         accounts
// @Accept       json
// @Produce      json
// @Param        body  body      AccountGetRequest  true  "Account identifier"
// @Success      200   {object}  AccountMeta
// @Failure      400   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/accounts/get [post]
func (c *Client) getAccount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AccountGetRequest
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

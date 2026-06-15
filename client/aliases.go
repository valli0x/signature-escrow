package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const aliasesKey = "aliases/all"

// Aliases are personal labels for addresses (partners / escrow / any address),
// stored locally so the user doesn't have to read raw hex everywhere.
type AliasesResponse struct {
	Aliases map[string]string `json:"aliases"` // lowercased address -> name
}

func (c *Client) loadAliases() map[string]string {
	data, err := c.stor.Get(context.Background(), aliasesKey)
	if err != nil || data == nil {
		return map[string]string{}
	}
	m := map[string]string{}
	if err := cbor.Unmarshal(data, &m); err != nil {
		return map[string]string{}
	}
	return m
}

func (c *Client) saveAliases(m map[string]string) {
	if b, err := cbor.Marshal(m); err == nil {
		_ = c.stor.Put(context.Background(), aliasesKey, b)
	}
}

// listAliases godoc
//
//	@Summary	List address aliases
//	@Tags		aliases
//	@Produce	json
//	@Success	200	{object}	AliasesResponse
//	@Router		/v1/aliases/list [get]
func (c *Client) listAliases() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respondOk(w, AliasesResponse{Aliases: c.loadAliases()})
	}
}

// setAlias godoc
//
//	@Summary	Set an address alias
//	@Tags		aliases
//	@Accept		json
//	@Produce	json
//	@Param		body	body		object	true	"address + name"
//	@Success	200		{object}	map[string]interface{}
//	@Router		/v1/aliases/set [post]
func (c *Client) setAlias() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address string `json:"address"`
			Name    string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		addr := strings.ToLower(strings.TrimSpace(req.Address))
		if addr == "" {
			respondError(w, http.StatusBadRequest, errors.New("address is required"))
			return
		}
		m := c.loadAliases()
		name := strings.TrimSpace(req.Name)
		if name == "" {
			delete(m, addr)
		} else {
			m[addr] = name
		}
		c.saveAliases(m)
		respondOk(w, map[string]any{"ok": true})
	}
}

// deleteAlias godoc
//
//	@Summary	Delete an address alias
//	@Tags		aliases
//	@Accept		json
//	@Produce	json
//	@Param		body	body		object	true	"address"
//	@Success	200		{object}	map[string]interface{}
//	@Router		/v1/aliases/delete [post]
func (c *Client) deleteAlias() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		m := c.loadAliases()
		delete(m, strings.ToLower(strings.TrimSpace(req.Address)))
		c.saveAliases(m)
		respondOk(w, map[string]any{"ok": true})
	}
}

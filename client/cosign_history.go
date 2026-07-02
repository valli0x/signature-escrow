package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const cosignHistoryKey = "cosign-history/all"
const cosignHistoryMax = 200

type CosignEvent struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	Network   string `json:"network"`
	Index     int    `json:"index"`
	Escrow    string `json:"escrow"`
	To        string `json:"to"`
	Amount    string `json:"amount"`
	Hash      string `json:"hash"`
	Signature string `json:"signature,omitempty"`
	TxData    string `json:"tx_data,omitempty"`
	TxHash    string `json:"tx_hash,omitempty"`
	Error     string `json:"error,omitempty"`
	EscrowID  string `json:"escrow_id,omitempty"`
	Pub       string `json:"pub,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

type CosignHistoryResponse struct {
	Events []CosignEvent `json:"events"`
}

func parseAccountName(name string) (string, int) {
	parts := strings.SplitN(name, "/", 2)
	net := parts[0]
	idx := 0
	if len(parts) > 1 {
		idx, _ = strconv.Atoi(parts[1])
	}
	return net, idx
}

func (c *Client) loadCosignHistory() []CosignEvent {
	data, err := c.stor.Get(context.Background(), cosignHistoryKey)
	if err != nil || data == nil {
		return []CosignEvent{}
	}
	var list []CosignEvent
	if err := cbor.Unmarshal(data, &list); err != nil {
		return []CosignEvent{}
	}
	return list
}

func (c *Client) recordCosign(ev CosignEvent) {
	if ev.ID == "" {
		ev.ID = randID()
	}
	if ev.CreatedAt == 0 {
		ev.CreatedAt = time.Now().UnixMilli()
	}
	list := c.loadCosignHistory()
	list = append([]CosignEvent{ev}, list...)
	if len(list) > cosignHistoryMax {
		list = list[:cosignHistoryMax]
	}
	b, err := cbor.Marshal(list)
	if err != nil {
		return
	}
	_ = c.stor.Put(context.Background(), cosignHistoryKey, b)
}

func (c *Client) completeCosign() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Hash      string `json:"hash"`
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if req.Hash == "" || req.Signature == "" {
			respondError(w, http.StatusBadRequest, errors.New("hash and signature are required"))
			return
		}
		list := c.loadCosignHistory()
		updated := false
		for i := range list {
			if list[i].Hash == req.Hash && list[i].Role == "initiator" &&
				list[i].Status != "broadcast" {
				list[i].Status = "completed"
				list[i].Signature = req.Signature
				updated = true
			}
		}
		if updated {
			if b, err := cbor.Marshal(list); err == nil {
				_ = c.stor.Put(context.Background(), cosignHistoryKey, b)
			}
		}
		respondOk(w, map[string]any{"updated": updated})
	}
}

// listCosignHistory godoc
//
//	@Summary	List co-sign history
//	@Tags		incomplete-signature
//	@Produce	json
//	@Success	200	{object}	CosignHistoryResponse
//	@Router		/v1/cosign/history [get]
func (c *Client) listCosignHistory() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respondOk(w, CosignHistoryResponse{Events: c.loadCosignHistory()})
	}
}

// clearCosignHistory godoc
//
//	@Summary	Clear co-sign history
//	@Tags		incomplete-signature
//	@Produce	json
//	@Success	200	{object}	map[string]interface{}
//	@Router		/v1/cosign/history/clear [post]
func (c *Client) clearCosignHistory() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = c.stor.Delete(context.Background(), cosignHistoryKey)
		respondOk(w, map[string]any{"cleared": true})
	}
}

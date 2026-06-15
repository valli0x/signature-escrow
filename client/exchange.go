package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const exchangesKey = "exchanges/all"

// Exchange links two escrow addresses (any ETH/BTC) for a swap, shared between
// two participants. Business state lives here on the client.
type Exchange struct {
	ID        string `json:"id"`
	AddressA  string `json:"address_a"`
	AddressB  string `json:"address_b"`
	Partner   string `json:"partner"` // ETH address of the other participant
	Status    string `json:"status"`  // draft | proposed | accepted
	CreatedAt int64  `json:"created_at"`
}

type ExchangeListResponse struct {
	Exchanges []Exchange `json:"exchanges"`
}

// ExchangeCreateRequest creates an exchange draft. Both addresses are optional.
type ExchangeCreateRequest struct {
	AddressA string `json:"address_a"`
	AddressB string `json:"address_b"`
}

// ExchangeUpdateRequest updates an existing exchange. partner/status are
// applied only when non-empty (e.g. when proposing to a partner).
type ExchangeUpdateRequest struct {
	ID       string `json:"id"`
	AddressA string `json:"address_a"`
	AddressB string `json:"address_b"`
	Partner  string `json:"partner,omitempty"`
	Status   string `json:"status,omitempty"`
}

// ExchangeUpsertRequest create-or-replaces an exchange by id (used by the
// acceptor to import a proposed exchange under the same id).
type ExchangeUpsertRequest struct {
	ID       string `json:"id"`
	AddressA string `json:"address_a"`
	AddressB string `json:"address_b"`
	Partner  string `json:"partner"`
	Status   string `json:"status"`
}

// ExchangeDeleteRequest identifies an exchange to delete.
type ExchangeDeleteRequest struct {
	ID string `json:"id"`
}

func (c *Client) loadExchanges() ([]Exchange, error) {
	data, err := c.stor.Get(context.Background(), exchangesKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return []Exchange{}, nil
	}
	var list []Exchange
	if err := cbor.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (c *Client) saveExchanges(list []Exchange) error {
	data, err := cbor.Marshal(list)
	if err != nil {
		return err
	}
	return c.stor.Put(context.Background(), exchangesKey, data)
}

func randID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// listExchanges lists all exchanges.
//
// @Summary      List exchanges
// @Description  Return all locally stored exchange entries (newest first).
// @Tags         exchanges
// @Produce      json
// @Success      200  {object}  ExchangeListResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /v1/exchanges/list [get]
func (c *Client) listExchanges() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := c.loadExchanges()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		respondOk(w, ExchangeListResponse{Exchanges: list})
	}
}

// createExchange creates an exchange (draft; addresses optional).
//
// @Summary      Create exchange (draft)
// @Description  Create an exchange entry. Addresses are optional and can be filled in later via /update.
// @Tags         exchanges
// @Accept       json
// @Produce      json
// @Param        body  body      ExchangeCreateRequest  false  "Exchange addresses (optional)"
// @Success      200   {object}  Exchange
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/exchanges/create [post]
func (c *Client) createExchange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ExchangeCreateRequest
		// Body is optional; ignore decode errors (empty body => empty draft).
		_ = json.NewDecoder(r.Body).Decode(&req)

		list, err := c.loadExchanges()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		ex := Exchange{
			ID:        randID(),
			AddressA:  req.AddressA,
			AddressB:  req.AddressB,
			CreatedAt: time.Now().UnixMilli(),
		}
		list = append([]Exchange{ex}, list...) // newest first

		if err := c.saveExchanges(list); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save exchange"))
			return
		}
		respondOk(w, ex)
	}
}

// updateExchange updates an exchange's addresses.
//
// @Summary      Update exchange
// @Description  Update the addresses of an existing exchange identified by id.
// @Tags         exchanges
// @Accept       json
// @Produce      json
// @Param        body  body      ExchangeUpdateRequest  true  "Exchange id and addresses"
// @Success      200   {object}  Exchange
// @Failure      400   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/exchanges/update [post]
func (c *Client) updateExchange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ExchangeUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.ID == "" {
			respondError(w, http.StatusBadRequest, errors.New("id is required"))
			return
		}

		list, err := c.loadExchanges()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		var updated *Exchange
		for i := range list {
			if list[i].ID == req.ID {
				list[i].AddressA = req.AddressA
				list[i].AddressB = req.AddressB
				if req.Partner != "" {
					list[i].Partner = req.Partner
				}
				if req.Status != "" {
					list[i].Status = req.Status
				}
				updated = &list[i]
				break
			}
		}
		if updated == nil {
			respondError(w, http.StatusNotFound, errors.New("exchange not found"))
			return
		}

		if err := c.saveExchanges(list); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save exchange"))
			return
		}
		respondOk(w, *updated)
	}
}

// upsertExchange creates or replaces an exchange by id (acceptor imports a
// proposed exchange under the initiator's id).
//
//	@Summary	Upsert exchange
//	@Tags		exchanges
//	@Accept		json
//	@Produce	json
//	@Param		body	body		ExchangeUpsertRequest	true	"Exchange"
//	@Success	200		{object}	Exchange
//	@Router		/v1/exchanges/upsert [post]
func (c *Client) upsertExchange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ExchangeUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.ID == "" {
			respondError(w, http.StatusBadRequest, errors.New("id is required"))
			return
		}

		list, err := c.loadExchanges()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		var found *Exchange
		for i := range list {
			if list[i].ID == req.ID {
				list[i].AddressA = req.AddressA
				list[i].AddressB = req.AddressB
				list[i].Partner = req.Partner
				list[i].Status = req.Status
				found = &list[i]
				break
			}
		}
		if found == nil {
			ex := Exchange{
				ID:        req.ID,
				AddressA:  req.AddressA,
				AddressB:  req.AddressB,
				Partner:   req.Partner,
				Status:    req.Status,
				CreatedAt: time.Now().UnixMilli(),
			}
			list = append([]Exchange{ex}, list...)
			found = &list[0]
		}

		if err := c.saveExchanges(list); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save exchange"))
			return
		}
		respondOk(w, *found)
	}
}

// deleteExchange deletes an exchange by id.
//
// @Summary      Delete exchange
// @Description  Delete an exchange entry identified by id.
// @Tags         exchanges
// @Accept       json
// @Produce      json
// @Param        body  body      ExchangeDeleteRequest  true  "Exchange id"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/exchanges/delete [post]
func (c *Client) deleteExchange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ExchangeDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.ID == "" {
			respondError(w, http.StatusBadRequest, errors.New("id is required"))
			return
		}

		list, err := c.loadExchanges()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		out := make([]Exchange, 0, len(list))
		for _, e := range list {
			if e.ID != req.ID {
				out = append(out, e)
			}
		}
		if err := c.saveExchanges(out); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to delete exchange"))
			return
		}
		respondOk(w, map[string]any{"deleted": true})
	}
}

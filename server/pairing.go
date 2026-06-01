package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/valli0x/signature-escrow/auth"
	"github.com/valli0x/signature-escrow/storage"
)

// Pair statuses
const (
	PairStatusPending  = "pending"
	PairStatusAccepted = "accepted"
)

// Storage key prefixes
const (
	pairPrefix = "pairs/"
)

// Pair represents a pairing request between two ETH addresses.
type Pair struct {
	ID        string `json:"id"`
	Initiator string `json:"initiator"`
	Partner   string `json:"partner"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

// Request/response types

type PairCreateRequest struct {
	Partner string `json:"partner"`
}

type PairCreateResponse struct {
	ID        string `json:"id"`
	Initiator string `json:"initiator"`
	Partner   string `json:"partner"`
	Status    string `json:"status"`
}

type PairAcceptRequest struct {
	ID string `json:"id"`
}

type PairAcceptResponse struct {
	ID        string `json:"id"`
	Initiator string `json:"initiator"`
	Partner   string `json:"partner"`
	Status    string `json:"status"`
}

type PairPendingResponse struct {
	Incoming []Pair `json:"incoming"`
	Outgoing []Pair `json:"outgoing"`
}

// pairID generates a deterministic pair ID from two addresses.
// Uses "_" separator (not ":") for filesystem compatibility.
func pairID(a, b string) string {
	a = strings.ToLower(strings.TrimPrefix(a, "0x"))
	b = strings.ToLower(strings.TrimPrefix(b, "0x"))
	if a < b {
		return a + "_" + b
	}
	return b + "_" + a
}

func storePair(stor storage.Storage, p *Pair) error {
	data, err := cbor.Marshal(p)
	if err != nil {
		return err
	}

	// Store by pair ID
	if err := stor.Put(context.Background(), pairPrefix+p.ID, data); err != nil {
		return err
	}

	// Index by initiator
	if err := addToIndex(stor, pairPrefix+"by-addr/"+strings.ToLower(p.Initiator), p.ID); err != nil {
		return err
	}

	// Index by partner
	if err := addToIndex(stor, pairPrefix+"by-addr/"+strings.ToLower(p.Partner), p.ID); err != nil {
		return err
	}

	return nil
}

func loadPair(stor storage.Storage, id string) (*Pair, error) {
	data, err := stor.Get(context.Background(), pairPrefix+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	p := &Pair{}
	if err := cbor.Unmarshal(data, p); err != nil {
		return nil, err
	}
	return p, nil
}

// deletePair removes a pair and its entries from both participants' indexes.
func deletePair(stor storage.Storage, p *Pair) error {
	if err := removeFromIndex(stor, pairPrefix+"by-addr/"+strings.ToLower(p.Initiator), p.ID); err != nil {
		return err
	}
	if err := removeFromIndex(stor, pairPrefix+"by-addr/"+strings.ToLower(p.Partner), p.ID); err != nil {
		return err
	}
	return stor.Delete(context.Background(), pairPrefix+p.ID)
}

// addToIndex appends a pair ID to an address's index list.
func addToIndex(stor storage.Storage, key, pairID string) error {
	var ids []string

	data, err := stor.Get(context.Background(), key)
	if err != nil {
		return err
	}
	if data != nil {
		if err := cbor.Unmarshal(data, &ids); err != nil {
			return err
		}
	}

	// Avoid duplicates
	for _, id := range ids {
		if id == pairID {
			return nil
		}
	}

	ids = append(ids, pairID)
	newData, err := cbor.Marshal(ids)
	if err != nil {
		return err
	}
	return stor.Put(context.Background(), key, newData)
}

func loadIndex(stor storage.Storage, address string) ([]string, error) {
	data, err := stor.Get(context.Background(), pairPrefix+"by-addr/"+strings.ToLower(address))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var ids []string
	if err := cbor.Unmarshal(data, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// Handlers

func (s *Server) pairCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PairCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Partner == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("partner address is required"))
			return
		}

		initiator := auth.AddressFromContext(r.Context())
		partner := strings.ToLower(req.Partner)

		if strings.EqualFold(initiator, partner) {
			respondError(w, http.StatusBadRequest, fmt.Errorf("cannot pair with yourself"))
			return
		}

		id := pairID(initiator, partner)

		// Check if pair already exists
		existing, err := loadPair(s.stor, id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if existing != nil {
			respondOk(w, PairCreateResponse{
				ID:        existing.ID,
				Initiator: existing.Initiator,
				Partner:   existing.Partner,
				Status:    existing.Status,
			})
			return
		}

		pair := &Pair{
			ID:        id,
			Initiator: initiator,
			Partner:   partner,
			Status:    PairStatusPending,
			CreatedAt: time.Now().Unix(),
		}

		if err := storePair(s.stor, pair); err != nil {
			s.logger.Error("failed to store pair", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create pair"))
			return
		}

		s.logger.Info("pair created", "initiator", initiator, "partner", partner, "id", id)

		respondOk(w, PairCreateResponse{
			ID:        pair.ID,
			Initiator: pair.Initiator,
			Partner:   pair.Partner,
			Status:    pair.Status,
		})
	}
}

func (s *Server) pairAccept() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PairAcceptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.ID == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("pair id is required"))
			return
		}

		myAddr := auth.AddressFromContext(r.Context())

		pair, err := loadPair(s.stor, req.ID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if pair == nil {
			respondError(w, http.StatusNotFound, fmt.Errorf("pair not found"))
			return
		}

		// Only the partner can accept
		if !strings.EqualFold(pair.Partner, myAddr) {
			respondError(w, http.StatusForbidden, fmt.Errorf("only the partner can accept this pair"))
			return
		}

		if pair.Status == PairStatusAccepted {
			respondOk(w, PairAcceptResponse{
				ID:        pair.ID,
				Initiator: pair.Initiator,
				Partner:   pair.Partner,
				Status:    pair.Status,
			})
			return
		}

		pair.Status = PairStatusAccepted

		// Re-store with updated status
		data, err := cbor.Marshal(pair)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("marshal error"))
			return
		}
		if err := s.stor.Put(context.Background(), pairPrefix+pair.ID, data); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		s.logger.Info("pair accepted", "partner", myAddr, "initiator", pair.Initiator, "id", pair.ID)

		respondOk(w, PairAcceptResponse{
			ID:        pair.ID,
			Initiator: pair.Initiator,
			Partner:   pair.Partner,
			Status:    pair.Status,
		})
	}
}

func (s *Server) pairPending() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		myAddr := auth.AddressFromContext(r.Context())

		ids, err := loadIndex(s.stor, myAddr)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		resp := PairPendingResponse{
			Incoming: make([]Pair, 0),
			Outgoing: make([]Pair, 0),
		}

		for _, id := range ids {
			pair, err := loadPair(s.stor, id)
			if err != nil || pair == nil {
				continue
			}

			if strings.EqualFold(pair.Partner, myAddr) {
				resp.Incoming = append(resp.Incoming, *pair)
			} else {
				resp.Outgoing = append(resp.Outgoing, *pair)
			}
		}

		respondOk(w, resp)
	}
}

// pairDelete removes a pair from the server entirely (both participants lose
// it). Only a member of the pair may delete it. The pair must be re-created to
// pair again.
func (s *Server) pairDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PairAcceptRequest // reuses {id}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.ID == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("pair id is required"))
			return
		}

		myAddr := auth.AddressFromContext(r.Context())
		pair, err := loadPair(s.stor, req.ID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if pair == nil {
			// Already gone — treat as success (idempotent).
			respondOk(w, map[string]any{"deleted": true})
			return
		}
		if !strings.EqualFold(pair.Initiator, myAddr) && !strings.EqualFold(pair.Partner, myAddr) {
			respondError(w, http.StatusForbidden, fmt.Errorf("you are not part of this pair"))
			return
		}

		if err := deletePair(s.stor, pair); err != nil {
			s.logger.Error("failed to delete pair", "error", err, "id", req.ID)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to delete pair"))
			return
		}

		s.logger.Info("pair deleted", "id", req.ID, "by", myAddr)
		respondOk(w, map[string]any{"deleted": true})
	}
}

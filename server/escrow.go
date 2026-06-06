package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/valli0x/signature-escrow/storage"
	"github.com/valli0x/signature-escrow/validation"
)

// Escrow data structures

type pollination struct {
	flower1, flower2 *flower
	m                sync.Mutex
}

type flower struct {
	ID             string
	Alg            validation.SignaturesType
	Pub, Hash, Sig []byte
}

func newPollination() *pollination {
	return &pollination{}
}

func (p *pollination) pollinate() (bool, error) {
	p.m.Lock()
	defer p.m.Unlock()

	if p.flower1 == nil || p.flower2 == nil {
		return false, nil
	}

	f1 := p.flower1
	f2 := p.flower2

	f1Pollinated, err := validation.Validate(f1.Alg, f1.Pub, f1.Hash, f2.Sig)
	if err != nil {
		return false, err
	}

	f2Pollinated, err := validation.Validate(f2.Alg, f2.Pub, f2.Hash, f1.Sig)
	if err != nil {
		return false, err
	}

	return f1Pollinated && f2Pollinated, nil
}

func (p *pollination) addFlower(f *flower) {
	switch {
	case p.flower1 == nil || string(p.flower1.Pub) == string(f.Pub):
		p.flower1 = f
	case p.flower2 == nil || string(p.flower2.Pub) == string(f.Pub):
		p.flower2 = f
	}
}

type pollinationMarshal struct {
	Flower1, Flower2 *flower
}

func (p *pollination) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(&pollinationMarshal{
		Flower1: p.flower1,
		Flower2: p.flower2,
	})
}

func (p *pollination) UnmarshalBinary(data []byte) error {
	pm := &pollinationMarshal{}
	if err := cbor.Unmarshal(data, pm); err != nil {
		return err
	}
	p.flower1 = pm.Flower1
	p.flower2 = pm.Flower2
	return nil
}

func getPollination(id string, stor storage.Storage) (*pollination, error) {
	data, err := stor.Get(context.Background(), id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	p := &pollination{}
	if err := p.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return p, nil
}

func putPollination(id string, p *pollination, stor storage.Storage) error {
	data, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	return stor.Put(context.Background(), id, data)
}

// Escrow handler

type EscrowRequest struct {
	Alg  string `json:"alg"`
	ID   string `json:"id"`
	Pub  string `json:"pub"`
	Hash string `json:"hash"`
	Sig  string `json:"sig"`
}

const (
	maxEscrowIDLen = 128
	hashLen        = 32 // Keccak256 / SHA256
	pubLenECDSA    = 33 // compressed secp256k1
	pubLenFrost    = 32 // x-only taproot
	maxSigLen      = 128
)

// parseEscrowRequest decodes JSON, validates fields, and returns a flower.
func parseEscrowRequest(r *http.Request) (*flower, error) {
	var req EscrowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("error parsing JSON")
	}

	if req.Alg == "" || req.ID == "" || req.Pub == "" || req.Hash == "" {
		return nil, fmt.Errorf("alg, id, pub and hash are required")
	}

	alg := validation.SignaturesType(req.Alg)
	if alg != validation.ECDSA && alg != validation.Frost {
		return nil, fmt.Errorf("alg must be %q or %q", validation.ECDSA, validation.Frost)
	}

	if len(req.ID) > maxEscrowIDLen {
		return nil, fmt.Errorf("id too long (max %d chars)", maxEscrowIDLen)
	}

	pub, err := hex.DecodeString(req.Pub)
	if err != nil {
		return nil, fmt.Errorf("invalid pub hex: %w", err)
	}
	if err := validatePub(alg, pub); err != nil {
		return nil, err
	}

	hash, err := hex.DecodeString(req.Hash)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(hash) != hashLen {
		return nil, fmt.Errorf("hash must be %d bytes, got %d", hashLen, len(hash))
	}

	var sig []byte
	if req.Sig != "" {
		sig, err = hex.DecodeString(req.Sig)
		if err != nil {
			return nil, fmt.Errorf("invalid sig hex: %w", err)
		}
		if len(sig) > maxSigLen {
			return nil, fmt.Errorf("sig too long (max %d bytes), got %d", maxSigLen, len(sig))
		}
	}

	return &flower{
		ID:   req.ID,
		Alg:  alg,
		Pub:  pub,
		Hash: hash,
		Sig:  sig,
	}, nil
}

// escrow submits a flower (pub/hash/sig) and pollinates a 2-party escrow.
//
// @Summary      Submit an escrow flower
// @Description  Submits one party's pub/hash/sig for an escrow ID. When both parties' signatures validate, returns status "complete" with the counterparty signature; otherwise status "pending".
// @Tags         escrow
// @Accept       json
// @Produce      json
// @Param        body  body      EscrowRequest  true  "Escrow flower"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Security     BearerAuth
// @Router       /v1/escrow [post]
func (s *Server) escrow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := parseEscrowRequest(r)
		if err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		pubB := f.Pub

		p, err := getPollination(f.ID, s.stor)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		if p == nil {
			p = newPollination()
			p.addFlower(f)
			if err := putPollination(f.ID, p, s.stor); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
				return
			}
			respondOk(w, map[string]any{"status": "pending"})
			return
		}

		p.addFlower(f)
		if err := putPollination(f.ID, p, s.stor); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		pollinated, err := p.pollinate()
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("validation failed"))
			return
		}

		if pollinated {
			var theirSig []byte
			switch {
			case string(p.flower1.Pub) == string(pubB):
				theirSig = p.flower2.Sig
			case string(p.flower2.Pub) == string(pubB):
				theirSig = p.flower1.Sig
			}

			// Race с timebox-выводом разрешает сама блокчейн-сеть:
			// одна транзакция тратит UTXO/nonce, вторая отвалится как
			// double-spend. Серверу не нужно атомарно гасить timebox.

			respondOk(w, map[string]any{
				"status":    "complete",
				"signature": base64.StdEncoding.EncodeToString(theirSig),
			})
			return
		}

		respondOk(w, map[string]any{"status": "pending"})
	}
}


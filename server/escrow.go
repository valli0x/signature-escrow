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
	"github.com/valli0x/signature-escrow/auth"
	"github.com/valli0x/signature-escrow/storage"
	"github.com/valli0x/signature-escrow/validation"
)

type pollination struct {
	flower1, flower2 *flower
	m                sync.Mutex
}

type flower struct {
	ID             string
	Alg            validation.SignaturesType
	Pub, Hash, Sig []byte
	// Depositor is the authenticated address that submitted this flower.
	// A slot can only be (re)written by its original depositor, and one
	// depositor cannot occupy both slots.
	Depositor string
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

func (p *pollination) addFlower(f *flower) error {
	// Same pub → same slot: only the original depositor may touch it, and a
	// non-empty deposited signature is immutable (idempotent re-post allowed).
	for _, slot := range []**flower{&p.flower1, &p.flower2} {
		ex := *slot
		if ex == nil || string(ex.Pub) != string(f.Pub) {
			continue
		}
		if ex.Depositor != "" && ex.Depositor != f.Depositor {
			return fmt.Errorf("this escrow slot belongs to another participant")
		}
		if len(ex.Sig) > 0 && string(ex.Sig) != string(f.Sig) {
			return fmt.Errorf("a different signature is already deposited for this pub")
		}
		*slot = f
		return nil
	}
	// New pub → free slot; one depositor cannot hold both slots.
	other := p.flower1
	if other == nil {
		other = p.flower2
	}
	if other != nil && other.Depositor != "" && other.Depositor == f.Depositor {
		return fmt.Errorf("one participant cannot occupy both escrow slots")
	}
	switch {
	case p.flower1 == nil:
		p.flower1 = f
	case p.flower2 == nil:
		p.flower2 = f
	default:
		return fmt.Errorf("escrow already has two participants")
	}
	return nil
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

type EscrowRequest struct {
	Alg  string `json:"alg"`
	ID   string `json:"id"`
	Pub  string `json:"pub"`
	Hash string `json:"hash"`
	Sig  string `json:"sig"`
}

const (
	maxEscrowIDLen = 128
	hashLen        = 32
	pubLenECDSA    = 33
	pubLenFrost    = 32
	maxSigLen      = 128
)

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
		f.Depositor = auth.AddressFromContext(r.Context())
		pubB := f.Pub

		// The whole read-modify-write must be atomic: two concurrent deposits
		// would otherwise each load the old pollination and clobber the other's
		// flower (last-writer-wins on the stored blob).
		s.escrowMu.Lock()
		defer s.escrowMu.Unlock()

		p, err := getPollination(f.ID, s.stor)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		if p == nil {
			p = newPollination()
			if err := p.addFlower(f); err != nil {
				respondError(w, http.StatusConflict, err)
				return
			}
			if err := putPollination(f.ID, p, s.stor); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
				return
			}
			respondOk(w, map[string]any{"status": "pending"})
			return
		}

		if err := p.addFlower(f); err != nil {
			respondError(w, http.StatusConflict, err)
			return
		}
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

			respondOk(w, map[string]any{
				"status":    "complete",
				"signature": base64.StdEncoding.EncodeToString(theirSig),
			})
			return
		}

		respondOk(w, map[string]any{"status": "pending"})
	}
}

type EscrowCheckRequest struct {
	ID  string `json:"id"`
	Pub string `json:"pub"`
}

// escrowCheck returns the released counterparty signature for {id, pub} once
// both flowers are present and valid; otherwise "pending". Read-only (no deposit).
//
//	@Summary	Check/poll an escrow pollination
//	@Tags		escrow
//	@Accept		json
//	@Produce	json
//	@Param		body	body		EscrowCheckRequest	true	"id + pub"
//	@Success	200		{object}	map[string]interface{}
//	@Security	BearerAuth
//	@Router		/v1/escrow/check [post]
func (s *Server) escrowCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req EscrowCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request"))
			return
		}
		if req.ID == "" || req.Pub == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("id and pub are required"))
			return
		}
		pubB, err := hex.DecodeString(req.Pub)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid pub hex"))
			return
		}
		p, err := getPollination(req.ID, s.stor)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if p == nil || p.flower1 == nil || p.flower2 == nil {
			respondOk(w, map[string]any{"status": "pending"})
			return
		}
		// Release only to whoever deposited this pub's flower (legacy flowers
		// without a recorded depositor stay poll-able by any authenticated user).
		caller := auth.AddressFromContext(r.Context())
		for _, fl := range []*flower{p.flower1, p.flower2} {
			if fl != nil && string(fl.Pub) == string(pubB) &&
				fl.Depositor != "" && fl.Depositor != caller {
				respondError(w, http.StatusForbidden, fmt.Errorf("this escrow slot belongs to another participant"))
				return
			}
		}
		pollinated, err := p.pollinate()
		if err != nil || !pollinated {
			respondOk(w, map[string]any{"status": "pending"})
			return
		}
		var theirSig []byte
		switch {
		case string(p.flower1.Pub) == string(pubB):
			theirSig = p.flower2.Sig
		case string(p.flower2.Pub) == string(pubB):
			theirSig = p.flower1.Sig
		}
		respondOk(w, map[string]any{
			"status":    "complete",
			"signature": base64.StdEncoding.EncodeToString(theirSig),
		})
	}
}

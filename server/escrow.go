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

func (p *pollination) getFlower(pub []byte) *flower {
	if p.flower1 != nil && string(p.flower1.Pub) == string(pub) {
		return p.flower1
	}
	if p.flower2 != nil && string(p.flower2.Pub) == string(pub) {
		return p.flower2
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

// Escrow handler

type EscrowRequest struct {
	Alg  string `json:"alg"`
	ID   string `json:"id"`
	Pub  string `json:"pub"`
	Hash string `json:"hash"`
	Sig  string `json:"sig"`
}

func (s *Server) escrow() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req EscrowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("error parsing JSON"))
			return
		}

		if req.Alg == "" || req.ID == "" || req.Pub == "" || req.Hash == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("alg, id, pub and hash are required"))
			return
		}

		pubB, err := hex.DecodeString(req.Pub)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid pub hex"))
			return
		}

		hashB, err := hex.DecodeString(req.Hash)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid hash hex"))
			return
		}

		var sigB []byte
		if req.Sig != "" {
			sigB, err = hex.DecodeString(req.Sig)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf("invalid sig hex"))
				return
			}
		}

		f := &flower{
			ID:   req.ID,
			Alg:  validation.SignaturesType(req.Alg),
			Pub:  pubB,
			Hash: hashB,
			Sig:  sigB,
		}

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
			respondOk(w, nil)
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
			if fl := p.getFlower(pubB); fl != nil {
				respondOk(w, map[string]string{
					"signature": base64.StdEncoding.EncodeToString(fl.Sig),
				})
				return
			}
		}

		respondOk(w, nil)
	}
}

func (s *Server) timebox() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: time-locked escrow
	}
}

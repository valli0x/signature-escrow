package keyserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
)

func (s *Server) keygenECDSA() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KeygenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Name == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("name, my_id, and another_id are required"))
			return
		}

		// Validate and format IDs
		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]
		signers := party.IDSlice{party.ID(myid), party.ID(another)}

		// Setup network connection
		net, err := redis.NewRedisNet(s.env.Communication, myid, another, s.logger.Named("network"))
		if err != nil {
			s.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		// Setup pool
		pl := pool.NewPool(0)
		defer pl.TearDown()

		s.logger.Info("Starting ECDSA keygen", "name", req.Name, "myid", myid)

		// Generate ECDSA key
		configETH, err := mpccmp.CMPKeygen(party.ID(myid), signers, 1, net, pl)
		if err != nil {
			s.logger.Error("ECDSA keygen failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("ECDSA keygen failed: %w", err))
			return
		}

		// Generate presignature
		presignature, err := mpccmp.CMPPreSign(configETH, signers, net, pl)
		if err != nil {
			s.logger.Error("ECDSA presign failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("ECDSA presign failed: %w", err))
			return
		}

		// Get address
		address, err := mpccmp.GetAddress(configETH)
		if err != nil {
			s.logger.Error("Failed to get ECDSA address", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get address: %w", err))
			return
		}

		// Get public key (for response)
		pubKeyData, err := mpccmp.GetPublicKeyByte(configETH)
		if err != nil {
			s.logger.Error("Failed to get ECDSA public key", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get public key: %w", err))
			return
		}

		// Save configuration
		kb, err := configETH.MarshalBinary()
		if err != nil {
			s.logger.Error("Failed to marshal ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal config: %w", err))
			return
		}

		preSignB, err := cbor.Marshal(presignature)
		if err != nil {
			s.logger.Error("Failed to marshal presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal presignature: %w", err))
			return
		}

		if err := s.stor.Put(context.Background(), req.Name+"/"+address+"/conf-ecdsa", kb); err != nil {
			s.logger.Error("Failed to save ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save config: %w", err))
			return
		}

		if err := s.stor.Put(context.Background(), req.Name+"/"+address+"/presig-ecdsa", preSignB); err != nil {
			s.logger.Error("Failed to save presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save presignature: %w", err))
			return
		}

		response := KeygenECDSAResponse{
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			Address:   address,
		}

		s.logger.Info("ECDSA keygen completed", "address", address)
		respondOk(w, response)
	}
}

package keyserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/network"
)

type KeygenRequest struct {
	Name    string `json:"name"`
	MyID    string `json:"my_id"`
	Another string `json:"another_id"`
}

type KeygenECDSAResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

func (s *Server) keygenECDSA() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KeygenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidRequest, err))
			return
		}

		if req.Name == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, errors.New(ErrNameMyIDAnotherRequired))
			return
		}

		// Validate and format IDs
		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]
		signers := party.IDSlice{party.ID(myid), party.ID(another)}

		// Setup network connection
		net, err := network.NewClient(s.env.Communication, myid, another, s.logger.With("component", "network"), s.Conn)
		if err != nil {
			s.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrNetworkSetupFailed, err))
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
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrECDSAKeygenFailed, err))
			return
		}

		// Generate presignature
		presignature, err := mpccmp.CMPPreSign(configETH, signers, net, pl)
		if err != nil {
			s.logger.Error("ECDSA presign failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrECDSAPresignFailed, err))
			return
		}

		// Get address
		address, err := mpccmp.GetAddress(configETH)
		if err != nil {
			s.logger.Error("Failed to get ECDSA address", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetAddress, err))
			return
		}

		// Get public key (for response)
		pubKeyData, err := mpccmp.GetPublicKeyByte(configETH)
		if err != nil {
			s.logger.Error("Failed to get ECDSA public key", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetPublicKey, err))
			return
		}

		// Save configuration
		kb, err := configETH.MarshalBinary()
		if err != nil {
			s.logger.Error("Failed to marshal ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToMarshalConfig, err))
			return
		}

		preSignB, err := cbor.Marshal(presignature)
		if err != nil {
			s.logger.Error("Failed to marshal presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToMarshalPresign, err))
			return
		}

		keyConfig := req.Name + "/" + address + "/conf-ecdsa"
		if err := s.stor.Put(context.Background(), keyConfig, kb); err != nil {
			s.logger.Error("Failed to save ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToSaveConfig, err))
			return
		}

		preSignConfig := req.Name + "/" + address + "/presig-ecdsa"
		if err := s.stor.Put(context.Background(), preSignConfig, preSignB); err != nil {
			s.logger.Error("Failed to save presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToSavePresign, err))
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

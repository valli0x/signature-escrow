package keyserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/valli0x/signature-escrow/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/network"
)

type KeygenFROSTResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

func (s *Server) keygenFROST() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KeygenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidRequest, err))
			return
		}

		if req.Name == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrNameMyIDAnotherRequired))
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

		s.logger.Info("Starting FROST keygen", "name", req.Name, "myid", myid)

		// Generate FROST key
		configBTC, err := mpcfrost.FrostKeygenTaproot(party.ID(myid), signers, 1, net)
		if err != nil {
			s.logger.Error("FROST keygen failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFrostKeygenFailed, err))
			return
		}

		// Get address
		address, err := mpcfrost.GetAddress(configBTC)
		if err != nil {
			s.logger.Error("Failed to get FROST address", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetAddress, err))
			return
		}

		// Get public key (for response)
		pubKeyData, err := mpcfrost.GetPublicKeyByte(configBTC)
		if err != nil {
			s.logger.Error("Failed to get FROST public key", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetPublicKey, err))
			return
		}

		// Save configuration
		configb, err := cbor.Marshal(configBTC)
		if err != nil {
			s.logger.Error("Failed to marshal FROST config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToMarshalConfig, err))
			return
		}

		if err := s.stor.Put(context.Background(), req.Name+"/"+address.String()+"/conf-frost", configb); err != nil {
			s.logger.Error("Failed to save FROST config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToSaveConfig, err))
			return
		}

		response := KeygenFROSTResponse{
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			Address:   address.String(),
		}

		s.logger.Info("FROST keygen completed", "address", address.String())
		respondOk(w, response)
	}
}

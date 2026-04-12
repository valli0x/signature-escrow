package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/valli0x/signature-escrow/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/network"
)

type KeygenFROSTResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

func (c *Client) keygenFROST() http.HandlerFunc {
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

		myid := normalizePartyID(req.MyID)
		another := normalizePartyID(req.Another)
		signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

		net, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		c.logger.Info("Starting FROST keygen", "name", req.Name, "myid", myid)

		configBTC, err := mpcfrost.FrostKeygenTaproot(party.ID(myid), signers, 1, net)
		if err != nil {
			c.logger.Error("FROST keygen failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("FROST keygen failed: %w", err))
			return
		}

		address, err := mpcfrost.GetAddress(configBTC)
		if err != nil {
			c.logger.Error("Failed to get FROST address", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get address: %w", err))
			return
		}

		pubKeyData, err := mpcfrost.GetPublicKeyByte(configBTC)
		if err != nil {
			c.logger.Error("Failed to get FROST public key", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get public key: %w", err))
			return
		}

		configb, err := cbor.Marshal(configBTC)
		if err != nil {
			c.logger.Error("Failed to marshal FROST config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal config: %w", err))
			return
		}

		if err := c.stor.Put(context.Background(), req.Name+"/"+address.String()+"/conf-frost", configb); err != nil {
			c.logger.Error("Failed to save FROST config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save config: %w", err))
			return
		}

		response := KeygenFROSTResponse{
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			Address:   address.String(),
		}

		c.logger.Info("FROST keygen completed", "address", address.String())
		respondOk(w, response)
	}
}

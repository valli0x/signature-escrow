package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/valli0x/signature-escrow/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/network"
)

type KeygenFROSTRequest struct {
	SessionID string `json:"session_id"`
	MyID      string `json:"my_id"`
	Another   string `json:"another_id"`
	Index     int    `json:"index"`
}

type KeygenFROSTResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	SessionID string `json:"session_id"`
	Index     int    `json:"index"`
}

func (c *Client) keygenFROST() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KeygenFROSTRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.SessionID == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, errors.New("session_id, my_id, and another_id are required"))
			return
		}

		if req.Index <= 0 {
			req.Index = 1
		}

		myid := normalizePartyID(req.MyID)
		another := normalizePartyID(req.Another)
		signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

		acceptCh := req.SessionID + "/" + myid
		sendCh := req.SessionID + "/" + another

		net, err := network.NewClient(c.env.Communication, acceptCh, sendCh, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		c.logger.Info("Starting FROST keygen", "session", req.SessionID, "myid", myid, "index", req.Index)

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

		storageBase := fmt.Sprintf("accounts/btc/%d", req.Index)

		configb, err := cbor.Marshal(configBTC)
		if err != nil {
			c.logger.Error("Failed to marshal FROST config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal config: %w", err))
			return
		}

		if err := c.stor.Put(context.Background(), storageBase+"/conf-frost", configb); err != nil {
			c.logger.Error("Failed to save FROST config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save config: %w", err))
			return
		}

		meta := AccountMeta{
			Network:   "btc",
			Index:     req.Index,
			Address:   address.String(),
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			PairMyID:  myid,
			PairOther: another,
			SessionID: req.SessionID,
		}
		metaB, _ := cbor.Marshal(meta)
		c.stor.Put(context.Background(), storageBase+"/meta", metaB)

		c.logger.Info("FROST keygen completed", "address", address.String(), "index", req.Index)

		respondOk(w, KeygenFROSTResponse{
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			Address:   address.String(),
			SessionID: req.SessionID,
			Index:     req.Index,
		})
	}
}

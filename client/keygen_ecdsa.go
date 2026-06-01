package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/network"
)

type KeygenECDSARequest struct {
	SessionID string `json:"session_id"`
	MyID      string `json:"my_id"`
	Another   string `json:"another_id"`
	Network   string `json:"network"`
	Index     int    `json:"index"`
}

type KeygenECDSAResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	SessionID string `json:"session_id"`
	Network   string `json:"network"`
	Index     int    `json:"index"`
}

func (c *Client) keygenECDSA() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KeygenECDSARequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.SessionID == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, errors.New("session_id, my_id, and another_id are required"))
			return
		}

		if err := validateSessionID(req.SessionID); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if err := validateETHAddress(req.MyID); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("my_id: %w", err))
			return
		}
		if err := validateETHAddress(req.Another); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("another_id: %w", err))
			return
		}

		if req.Network == "" {
			req.Network = "eth"
		}
		if err := validateNetwork(req.Network); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}

		if req.Index <= 0 {
			req.Index = 1
		}
		if err := validateIndex(req.Index); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}

		myid := normalizePartyID(req.MyID)
		another := normalizePartyID(req.Another)
		signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

		// NATS channels prefixed with session_id for isolation
		acceptCh := req.SessionID + "/" + myid
		sendCh := req.SessionID + "/" + another

		net, err := network.NewClient(c.env.Communication, acceptCh, sendCh, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		pl := pool.NewPool(0)
		defer pl.TearDown()

		c.logger.Info("Starting ECDSA keygen", "session", req.SessionID, "myid", myid, "network", req.Network, "index", req.Index)

		configETH, err := mpccmp.CMPKeygen(party.ID(myid), signers, 1, net, pl)
		if err != nil {
			c.logger.Error("ECDSA keygen failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("ECDSA keygen failed: %w", err))
			return
		}

		// Presign with new connection. Use a distinct subject suffix so the
		// relay's per-subject consumer does not collide with the keygen phase
		// (both parties derive the same "/presign" subjects deterministically).
		net2, err := network.NewClient(c.env.Communication, acceptCh+"/presign", sendCh+"/presign", c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network for presign", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		presignature, err := mpccmp.CMPPreSign(configETH, signers, net2, pl)
		if err != nil {
			c.logger.Error("ECDSA presign failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("ECDSA presign failed: %w", err))
			return
		}

		address, err := mpccmp.GetAddress(configETH)
		if err != nil {
			c.logger.Error("Failed to get ECDSA address", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get address: %w", err))
			return
		}

		pubKeyData, err := mpccmp.GetPublicKeyByte(configETH)
		if err != nil {
			c.logger.Error("Failed to get ECDSA public key", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get public key: %w", err))
			return
		}

		// Save locally: accounts/{network}/{index}/conf-ecdsa
		storageBase := fmt.Sprintf("accounts/%s/%d", req.Network, req.Index)

		kb, err := configETH.MarshalBinary()
		if err != nil {
			c.logger.Error("Failed to marshal ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal config: %w", err))
			return
		}

		preSignB, err := cbor.Marshal(presignature)
		if err != nil {
			c.logger.Error("Failed to marshal presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal presign: %w", err))
			return
		}

		if err := c.stor.Put(context.Background(), storageBase+"/conf-ecdsa", kb); err != nil {
			c.logger.Error("Failed to save ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save config: %w", err))
			return
		}

		if err := c.stor.Put(context.Background(), storageBase+"/presig-ecdsa", preSignB); err != nil {
			c.logger.Error("Failed to save presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save presign: %w", err))
			return
		}

		// Save account metadata
		meta := AccountMeta{
			Network:   req.Network,
			Index:     req.Index,
			Address:   address,
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			PairMyID:  myid,
			PairOther: another,
			SessionID: req.SessionID,
		}
		metaB, _ := cbor.Marshal(meta)
		c.stor.Put(context.Background(), storageBase+"/meta", metaB)

		c.logger.Info("ECDSA keygen completed", "address", address, "network", req.Network, "index", req.Index)

		respondOk(w, KeygenECDSAResponse{
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			Address:   address,
			SessionID: req.SessionID,
			Network:   req.Network,
			Index:     req.Index,
		})
	}
}

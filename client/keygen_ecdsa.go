package client

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

func (c *Client) keygenECDSA() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KeygenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Name == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, errors.New("name, my_id, and another_id are required"))
			return
		}

		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]
		signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

		net, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		pl := pool.NewPool(0)
		defer pl.TearDown()

		c.logger.Info("Starting ECDSA keygen", "name", req.Name, "myid", myid)

		configETH, err := mpccmp.CMPKeygen(party.ID(myid), signers, 1, net, pl)
		if err != nil {
			c.logger.Error("ECDSA keygen failed", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("ECDSA keygen failed: %w", err))
			return
		}

		net2, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
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

		keyConfig := req.Name + "/" + address + "/conf-ecdsa"
		if err := c.stor.Put(context.Background(), keyConfig, kb); err != nil {
			c.logger.Error("Failed to save ECDSA config", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save config: %w", err))
			return
		}

		preSignConfig := req.Name + "/" + address + "/presig-ecdsa"
		if err := c.stor.Put(context.Background(), preSignConfig, preSignB); err != nil {
			c.logger.Error("Failed to save presignature", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to save presign: %w", err))
			return
		}

		response := KeygenECDSAResponse{
			PublicKey: fmt.Sprintf("%x", pubKeyData),
			Address:   address,
		}

		c.logger.Info("ECDSA keygen completed", "address", address)
		respondOk(w, response)
	}
}

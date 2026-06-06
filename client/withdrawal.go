package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/network"
)

type SendWithdrawalTxRequest struct {
	Algorithm     string `json:"alg"`
	Name          string `json:"name"`
	EscrowAddress string `json:"escrow_address"`
	HashTx        string `json:"hash_tx"`
	MyID          string `json:"my_id"`
	Another       string `json:"another_id"`
}

type SendWithdrawalTxResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	// PresignRotated reports whether a fresh single-use presignature was
	// generated to replace the one just consumed (ECDSA only).
	PresignRotated bool `json:"presign_rotated"`
}

type AcceptWithdrawalTxRequest struct {
	Algorithm     string `json:"alg"`
	Name          string `json:"name"`
	EscrowAddress string `json:"escrow_address"`
	MyID          string `json:"my_id"`
	Another       string `json:"another_id"`
	// HashTx обязателен для FROST: протокол сам не пересылает хеш —
	// обе стороны должны знать, что подписывают, заранее (через mailbox/UI).
	// Для ECDSA не используется (хеш приходит в payload incomplete-signature).
	HashTx string `json:"hash_tx,omitempty"`
}

type AcceptWithdrawalTxResponse struct {
	Status            string `json:"status"`
	CompleteSignature string `json:"complete_signature"`
	Message           string `json:"message"`
	// PresignRotated reports whether a fresh single-use presignature was
	// generated to replace the one just consumed (ECDSA only).
	PresignRotated bool `json:"presign_rotated"`
}

// sendWithdrawalTx initiates the sender half of an MPC withdrawal signature.
//
// @Summary      Send incomplete signature
// @Description  Run the initiating half of an MPC withdrawal signature (ECDSA incomplete signature send, or FROST round2/round3 exchange).
// @Tags         incomplete-signature
// @Accept       json
// @Produce      json
// @Param        body  body      SendWithdrawalTxRequest  true  "Withdrawal signing parameters"
// @Success      200   {object}  SendWithdrawalTxResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/incomplete-signature/send [post]
func (c *Client) sendWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.HashTx == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("alg, name, escrow_address, hash_tx, my_id and another_id are required"))
			return
		}

		alg := req.Algorithm
		name := req.Name
		escrowAddress := req.EscrowAddress
		hashTxWithdrawal := req.HashTx
		myid := normalizePartyID(req.MyID)
		another := normalizePartyID(req.Another)

		// keygen wrote via c.stor (already encrypted when STORAGE_PASS is set);
		// read through the same layer — do NOT wrap again (double-encryption).
		stor := c.stor

		net, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		switch alg {
		case "ecdsa":
			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), "accounts/"+name+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get config: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal config: %v", err))
				return
			}

			presign := mpccmp.EmptyPreSign()
			data, err = stor.Get(context.Background(), "accounts/"+name+"/presig-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get presign: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, presign); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal presign: %v", err))
				return
			}

			pl := pool.NewPool(0)
			defer pl.TearDown()

			hashB, err := hex.DecodeString(hashTxWithdrawal)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf("invalid hash format: %v", err))
				return
			}

			incsig, err := mpccmp.CMPPreSignOnlineInc(config, presign, hashB, pl)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create incomplete signature: %v", err))
				return
			}

			incsigHex, err := mpccmp.MsgToHex(incsig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to convert signature to hex: %v", err))
				return
			}

			tx := struct {
				IncSig string `json:"inc_sig"`
				HashTx string `json:"hash_tx"`
			}{
				IncSig: incsigHex,
				HashTx: hashTxWithdrawal,
			}

			msg := &protocol.Message{}
			msg.Data, err = json.Marshal(tx)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal message: %v", err))
				return
			}
			net.Send(msg)

			// The presignature is single-use: it was just consumed by the
			// incomplete signature above. Regenerate it with the partner so the
			// next withdrawal can sign. Both sides run this round.
			rotated := c.rotateECDSAPresign(name, myid, another, config)

			response := SendWithdrawalTxResponse{
				Status:         "sent",
				Message:        "Incomplete signature sent successfully",
				PresignRotated: rotated,
			}
			respondOk(w, response)

		case "frost":
			config := &frost.TaprootConfig{}
			data, err := stor.Get(context.Background(), "accounts/"+name+"/conf-frost")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get frost config: %v", err))
				return
			}
			if data == nil {
				respondError(w, http.StatusNotFound, fmt.Errorf("frost config not found for %s/%s", name, escrowAddress))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal frost config: %v", err))
				return
			}

			hashB, err := hex.DecodeString(hashTxWithdrawal)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf("invalid hash format: %v", err))
				return
			}

			signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

			// FrostSignTaprootInc выполняет: send round2 → recv round2 → send round3.
			// Полную подпись соберёт принимающая сторона в acceptWithdrawalTx.
			if err := mpcfrost.FrostSignTaprootInc(config, hashB, signers, net); err != nil {
				c.logger.Error("FROST inc signing failed", "error", err)
				respondError(w, http.StatusInternalServerError, fmt.Errorf("frost inc signing failed: %v", err))
				return
			}

			respondOk(w, SendWithdrawalTxResponse{
				Status:  "sent",
				Message: "FROST partial signature exchanged (round2 + round3)",
			})

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}

// acceptWithdrawalTx completes the receiver half of an MPC withdrawal signature.
//
// @Summary      Accept incomplete signature
// @Description  Run the accepting half of an MPC withdrawal signature and return the complete signature (ECDSA co-sign, or FROST co-sign).
// @Tags         incomplete-signature
// @Accept       json
// @Produce      json
// @Param        body  body      AcceptWithdrawalTxRequest  true  "Withdrawal signing parameters"
// @Success      200   {object}  AcceptWithdrawalTxResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      404   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/incomplete-signature/accept [post]
func (c *Client) acceptWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AcceptWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("alg, name and escrow_address are required"))
			return
		}

		alg := req.Algorithm
		name := req.Name
		address := req.EscrowAddress
		myid := normalizePartyID(req.MyID)
		another := normalizePartyID(req.Another)

		// keygen wrote via c.stor (already encrypted when STORAGE_PASS is set);
		// read through the same layer — do NOT wrap again (double-encryption).
		stor := c.stor

		net, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		switch alg {
		case "ecdsa":
			// Wait for the initiator's incomplete signature, but don't hang
			// forever if they never send it.
			var msg *protocol.Message
			select {
			case msg = <-net.Next():
			case <-time.After(90 * time.Second):
				respondError(w, http.StatusGatewayTimeout,
					errors.New("timed out waiting for the other party's incomplete signature"))
				return
			}

			tx := struct {
				IncSig string `json:"inc_sig"`
				HashTx string `json:"hash_tx"`
			}{}

			if err := json.Unmarshal(msg.Data, &tx); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal message: %v", err))
				return
			}

			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), "accounts/"+name+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get config: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal config: %v", err))
				return
			}

			presign := mpccmp.EmptyPreSign()
			data, err = stor.Get(context.Background(), "accounts/"+name+"/presig-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get presign: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, presign); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal presign: %v", err))
				return
			}

			hashB, err := hex.DecodeString(tx.HashTx)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf("invalid hash format: %v", err))
				return
			}

			incsig, err := mpccmp.HexToMsg(tx.IncSig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to convert hex to message: %v", err))
				return
			}

			pl := pool.NewPool(0)
			defer pl.TearDown()

			sig, err := mpccmp.CMPPreSignOnlineCoSign(config, presign, hashB, incsig, pl)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to complete signature: %v", err))
				return
			}

			sigEthereum, err := mpccmp.GetSigByte(sig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get signature bytes: %v", err))
				return
			}

			completeSignature := hex.EncodeToString(sigEthereum)

			// Presignature consumed — regenerate it with the partner so the
			// next withdrawal can sign.
			rotated := c.rotateECDSAPresign(name, myid, another, config)

			response := AcceptWithdrawalTxResponse{
				Status:            "completed",
				CompleteSignature: completeSignature,
				Message:           "Another complete signature of the withdrawal transaction",
				PresignRotated:    rotated,
			}
			respondOk(w, response)

		case "frost":
			if req.HashTx == "" {
				respondError(w, http.StatusBadRequest, errors.New("hash_tx is required for FROST (both parties must know the hash in advance)"))
				return
			}

			hashB, err := hex.DecodeString(req.HashTx)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf("invalid hash format: %v", err))
				return
			}

			config := &frost.TaprootConfig{}
			data, err := stor.Get(context.Background(), "accounts/"+name+"/conf-frost")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get frost config: %v", err))
				return
			}
			if data == nil {
				respondError(w, http.StatusNotFound, fmt.Errorf("frost config not found for %s/%s", name, address))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal frost config: %v", err))
				return
			}

			signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

			// FrostSignTaprootCoSign выполняет: send round2 → recv round2 →
			// (skip own round3) → recv round3 → собрать полную подпись.
			// Параметр incSig в этой функции не используется — передаём nil.
			sig, err := mpcfrost.FrostSignTaprootCoSign(config, hashB, signers, net)
			if err != nil {
				c.logger.Error("FROST co-sign failed", "error", err)
				respondError(w, http.StatusInternalServerError, fmt.Errorf("frost co-sign failed: %v", err))
				return
			}

			respondOk(w, AcceptWithdrawalTxResponse{
				Status:            "completed",
				CompleteSignature: hex.EncodeToString(sig),
				Message:           "FROST signature completed",
			})

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}

// rotateECDSAPresign regenerates the single-use CMP presignature for an account
// after it was consumed by a signing operation. It is an interactive round —
// BOTH parties must run it (they meet on the "/rotate" relay subjects).
//
// On success the stored presignature is overwritten. On failure the consumed
// presignature is DELETED so it can never be silently reused (which would be
// insecure); the next signing attempt then fails loudly until a fresh presign
// is generated. The already-produced signature is never affected.
func (c *Client) rotateECDSAPresign(name, myid, another string, config *cmp.Config) bool {
	presigKey := "accounts/" + name + "/presig-ecdsa"

	signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

	net, err := network.NewClient(
		c.env.Communication,
		myid+"/rotate", another+"/rotate",
		c.logger.With("component", "network"), c.Conn,
	)
	if err != nil {
		c.logger.Error("presign rotation: network setup failed", "error", err)
		_ = c.stor.Delete(context.Background(), presigKey)
		return false
	}
	defer net.Done()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	newPresig, err := mpccmp.CMPPreSign(config, signers, net, pl)
	if err != nil {
		c.logger.Error("presign rotation failed", "error", err)
		_ = c.stor.Delete(context.Background(), presigKey)
		return false
	}

	b, err := cbor.Marshal(newPresig)
	if err != nil {
		c.logger.Error("presign rotation: marshal failed", "error", err)
		_ = c.stor.Delete(context.Background(), presigKey)
		return false
	}

	if err := c.stor.Put(context.Background(), presigKey, b); err != nil {
		c.logger.Error("presign rotation: save failed", "error", err)
		return false
	}

	c.logger.Info("presignature rotated", "account", name)
	return true
}

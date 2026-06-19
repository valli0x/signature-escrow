package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	ethtypes "github.com/ethereum/go-ethereum/core/types"
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
	// Optional tx context (history display + later broadcast from Activity).
	To     string `json:"to,omitempty"`
	Amount string `json:"amount,omitempty"`
	TxData string `json:"tx_data,omitempty"`
	// Escrow (atomic swap): when EscrowID is set, the initiator records an
	// escrow-await event so the signature is exchanged via the server escrow.
	EscrowID string `json:"escrow_id,omitempty"`
	Pub      string `json:"pub,omitempty"`
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
	// Optional tx context (for history + later broadcast from Activity).
	To     string `json:"to,omitempty"`
	Amount string `json:"amount,omitempty"`
	TxData string `json:"tx_data,omitempty"`
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

		// Per-round relay subjects (scoped by the tx hash) so consumers from
		// different co-sign rounds never collide ("filtered consumer not unique").
		net, err := network.NewClient(
			c.env.Communication,
			myid+"/cosign/"+hashTxWithdrawal, another+"/cosign/"+hashTxWithdrawal,
			c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}
		defer net.Done()

		switch alg {
		case "ecdsa":
			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), "accounts/"+name+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get config: %v", err))
				return
			}
			// Config is stored via cmp.Config.MarshalBinary (not plain cbor),
			// so it must be read back the same way.
			if err := config.UnmarshalBinary(data); err != nil {
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

			// Respond immediately — do NOT block the request on presignature
			// rotation. Rotation is an interactive round that can only complete
			// once the partner accepts; running it inline would hang the caller
			// until then. Run it in the background instead.
			go c.rotateECDSAPresign(name, myid, another, hashTxWithdrawal, config)

			net0, idx0 := parseAccountName(name)
			status0 := "sent"
			if req.EscrowID != "" {
				status0 = "escrow-await" // signature will arrive via server escrow
			}
			c.recordCosign(CosignEvent{
				Role: "initiator", Status: status0,
				Network: net0, Index: idx0, Escrow: escrowAddress,
				To: req.To, Amount: req.Amount, Hash: hashTxWithdrawal,
				TxData: req.TxData, EscrowID: req.EscrowID, Pub: req.Pub,
			})

			response := SendWithdrawalTxResponse{
				Status:         "sent",
				Message:        "Incomplete signature sent; presignature refreshing in background",
				PresignRotated: false,
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
		// hash_tx is required so both parties scope the relay subject identically.
		if req.HashTx == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("hash_tx is required"))
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

		// Per-round relay subjects (scoped by the tx hash) — must match the
		// sender's so the two halves rendezvous, and so rounds never collide.
		net, err := network.NewClient(
			c.env.Communication,
			myid+"/cosign/"+req.HashTx, another+"/cosign/"+req.HashTx,
			c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}
		defer net.Done()

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

			// SECURITY: only co-sign a hash that provably matches the tx_data we
			// were shown. Otherwise the initiator could DISPLAY a benign transfer
			// while asking us to sign a different transaction (e.g. draining the
			// escrow). Recompute the signing hash from tx_data and compare.
			if req.TxData != "" {
				raw, err := hex.DecodeString(strings.TrimPrefix(req.TxData, "0x"))
				if err != nil {
					respondError(w, http.StatusBadRequest, fmt.Errorf("invalid tx_data: %v", err))
					return
				}
				etx := new(ethtypes.Transaction)
				if err := etx.UnmarshalBinary(raw); err != nil {
					respondError(w, http.StatusBadRequest, fmt.Errorf("decode tx_data: %v", err))
					return
				}
				want := ethtypes.NewLondonSigner(big.NewInt(1)).Hash(etx)
				if !strings.EqualFold(hex.EncodeToString(want.Bytes()), tx.HashTx) {
					respondError(w, http.StatusBadRequest, errors.New(
						"refusing to sign: tx hash does not match tx_data (possible tampering)"))
					return
				}
			}

			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), "accounts/"+name+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get config: %v", err))
				return
			}
			// Config is stored via cmp.Config.MarshalBinary (not plain cbor),
			// so it must be read back the same way.
			if err := config.UnmarshalBinary(data); err != nil {
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

			// Ethereum format r||s||v (low-s, recovery id) so the node can
			// recover the sender. GetSigByte returns CMP-native R||S, which a
			// node cannot verify.
			sigEthereum, err := mpccmp.SigEthereum(sig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get signature bytes: %v", err))
				return
			}

			completeSignature := hex.EncodeToString(sigEthereum)

			// Return the signature immediately; refresh the consumed
			// presignature in the background (interactive round with the peer).
			go c.rotateECDSAPresign(name, myid, another, tx.HashTx, config)

			net0, idx0 := parseAccountName(name)
			c.recordCosign(CosignEvent{
				Role: "acceptor", Status: "completed",
				Network: net0, Index: idx0, Escrow: address,
				To: req.To, Amount: req.Amount, Hash: tx.HashTx,
				Signature: completeSignature, TxData: req.TxData,
			})

			response := AcceptWithdrawalTxResponse{
				Status:            "completed",
				CompleteSignature: completeSignature,
				Message:           "Another complete signature of the withdrawal transaction",
				PresignRotated:    false,
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
func (c *Client) rotateECDSAPresign(name, myid, another, roundID string, config *cmp.Config) bool {
	presigKey := "accounts/" + name + "/presig-ecdsa"

	signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

	// Per-round relay subjects (scoped by roundID, e.g. the tx hash) so rotations
	// from different signings — or a leftover one — never collide on the queue.
	net, err := network.NewClient(
		c.env.Communication,
		myid+"/rotate/"+roundID, another+"/rotate/"+roundID,
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

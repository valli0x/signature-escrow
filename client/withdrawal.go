package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/mpc/mpcfrost"
	"github.com/valli0x/signature-escrow/network"
	"github.com/valli0x/signature-escrow/storage"
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

		stor, err := storage.NewEncryptedStorage(c.stor, c.storagePass)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create encrypted storage: %v", err))
			return
		}

		net, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		switch alg {
		case "ecdsa":
			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get config: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal config: %v", err))
				return
			}

			presign := mpccmp.EmptyPreSign()
			data, err = stor.Get(context.Background(), name+"/"+escrowAddress+"/presign-ecdsa")
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

			response := SendWithdrawalTxResponse{
				Status:  "sent",
				Message: "Incomplete signature sent successfully",
			}
			respondOk(w, response)

		case "frost":
			config := &frost.TaprootConfig{}
			data, err := stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-frost")
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

		stor, err := storage.NewEncryptedStorage(c.stor, c.storagePass)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create encrypted storage: %v", err))
			return
		}

		net, err := network.NewClient(c.env.Communication, myid, another, c.logger.With("component", "network"), c.Conn)
		if err != nil {
			c.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("network setup failed: %w", err))
			return
		}

		switch alg {
		case "ecdsa":
			msg := <-net.Next()

			tx := struct {
				IncSig string `json:"inc_sig"`
				HashTx string `json:"hash_tx"`
			}{}

			if err := json.Unmarshal(msg.Data, &tx); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal message: %v", err))
				return
			}

			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), name+"/"+address+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get config: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal config: %v", err))
				return
			}

			presign := mpccmp.EmptyPreSign()
			data, err = stor.Get(context.Background(), name+"/"+address+"/presign-ecdsa")
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

			response := AcceptWithdrawalTxResponse{
				Status:            "completed",
				CompleteSignature: completeSignature,
				Message:           "Another complete signature of the withdrawal transaction",
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
			data, err := stor.Get(context.Background(), name+"/"+address+"/conf-frost")
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

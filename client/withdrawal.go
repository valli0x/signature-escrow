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
	To            string `json:"to,omitempty"`
	Amount        string `json:"amount,omitempty"`
	TxData        string `json:"tx_data,omitempty"`
	EscrowID      string `json:"escrow_id,omitempty"`
	Pub           string `json:"pub,omitempty"`
}

type SendWithdrawalTxResponse struct {
	Status         string `json:"status"`
	Message        string `json:"message"`
	PresignRotated bool   `json:"presign_rotated"`
}

type AcceptWithdrawalTxRequest struct {
	Algorithm     string `json:"alg"`
	Name          string `json:"name"`
	EscrowAddress string `json:"escrow_address"`
	MyID          string `json:"my_id"`
	Another       string `json:"another_id"`
	HashTx        string `json:"hash_tx,omitempty"`
	To            string `json:"to,omitempty"`
	Amount        string `json:"amount,omitempty"`
	TxData        string `json:"tx_data,omitempty"`
	EscrowID      string `json:"escrow_id,omitempty"`
}

type AcceptWithdrawalTxResponse struct {
	Status            string `json:"status"`
	CompleteSignature string `json:"complete_signature"`
	// EscrowSignature is the SAME signature in CMP-native encoding
	// ([33B R point][32B S scalar]) — the ONLY format the server's escrow
	// validation.Validate can verify. It MUST be captured BEFORE SigEthereum,
	// which negates S in place (low-s) and thereby breaks the point-equality
	// check in multi-party-sig's Verify.
	EscrowSignature string `json:"escrow_signature,omitempty"`
	Message         string `json:"message"`
	PresignRotated  bool   `json:"presign_rotated"`
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

		stor := c.stor

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

			incSig, err := mpccmp.CMPPreSignOnlineInc(config, presign, hashB, pl)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create incomplete signature: %v", err))
				return
			}

			incSigHex, err := mpccmp.MsgToHex(incSig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to convert signature to hex: %v", err))
				return
			}

			tx := struct {
				IncSig string `json:"inc_sig"`
				HashTx string `json:"hash_tx"`
			}{
				IncSig: incSigHex,
				HashTx: hashTxWithdrawal,
			}

			msg := &protocol.Message{}
			msg.Data, err = json.Marshal(tx)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal message: %v", err))
				return
			}
			net.Send(msg)

			go c.rotateECDSAPresign(name, myid, another, hashTxWithdrawal, config)

			net0, idx0 := parseAccountName(name)
			status0 := "sent"
			if req.EscrowID != "" {
				status0 = "escrow-await"
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
		if req.HashTx == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("hash_tx is required"))
			return
		}

		alg := req.Algorithm
		name := req.Name
		address := req.EscrowAddress
		myid := normalizePartyID(req.MyID)
		another := normalizePartyID(req.Another)

		if req.EscrowID != "" {
			for _, ev := range c.loadCosignHistory() {
				if ev.Role == "acceptor" && ev.EscrowID == req.EscrowID &&
					ev.Status == "completed" {
					respondError(w, http.StatusConflict, fmt.Errorf(
						"already co-signed once for this swap (escrow_id=%s) — refusing a second signature", req.EscrowID))
					return
				}
			}
		}

		stor := c.stor

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

			incSig, err := mpccmp.HexToMsg(tx.IncSig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to convert hex to message: %v", err))
				return
			}

			pl := pool.NewPool(0)
			defer pl.TearDown()

			sig, err := mpccmp.CMPPreSignOnlineCoSign(config, presign, hashB, incSig, pl)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to complete signature: %v", err))
				return
			}

			escrowSig, err := mpccmp.GetSigByte(sig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get escrow signature bytes: %v", err))
				return
			}

			sigEthereum, err := mpccmp.SigEthereum(sig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get signature bytes: %v", err))
				return
			}

			completeSignature := hex.EncodeToString(sigEthereum)
			escrowSignature := hex.EncodeToString(escrowSig)

			go c.rotateECDSAPresign(name, myid, another, tx.HashTx, config)

			net0, idx0 := parseAccountName(name)
			c.recordCosign(CosignEvent{
				Role: "acceptor", Status: "completed",
				Network: net0, Index: idx0, Escrow: address,
				To: req.To, Amount: req.Amount, Hash: tx.HashTx,
				Signature: completeSignature, TxData: req.TxData,
				EscrowID: req.EscrowID,
			})

			response := AcceptWithdrawalTxResponse{
				Status:            "completed",
				CompleteSignature: completeSignature,
				EscrowSignature:   escrowSignature,
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

			sig, err := mpcfrost.FrostSignTaprootCoSign(config, hashB, signers, net)
			if err != nil {
				c.logger.Error("FROST co-sign failed", "error", err)
				respondError(w, http.StatusInternalServerError, fmt.Errorf("frost co-sign failed: %v", err))
				return
			}

			respondOk(w, AcceptWithdrawalTxResponse{
				Status:            "completed",
				CompleteSignature: hex.EncodeToString(sig),
				EscrowSignature:   hex.EncodeToString(sig),
				Message:           "FROST signature completed",
			})

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}

func (c *Client) rotateECDSAPresign(name, myid, another, roundID string, config *cmp.Config) bool {
	presigKey := "accounts/" + name + "/presig-ecdsa"

	signers := party.NewIDSlice([]party.ID{party.ID(myid), party.ID(another)})

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

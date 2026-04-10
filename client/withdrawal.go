package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
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
}

type AcceptWithdrawalTxResponse struct {
	Status            string `json:"status"`
	CompleteSignature string `json:"complete_signature"`
	Message           string `json:"message"`
}

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
		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]

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
			respondError(w, http.StatusNotImplemented, errors.New("FROST algorithm not implemented yet"))
			return

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}

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
		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]

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
			msg := <-net.Next()
			_ = msg
			respondError(w, http.StatusNotImplemented, errors.New("FROST algorithm not implemented yet"))
			return

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}

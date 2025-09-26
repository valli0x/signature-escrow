package keyserver

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

// Command send the own withdrawal transaction with our incomplete signature
func (s *Server) sendWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidRequestBody, err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.HashTx == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrAlgNameEscrowHashRequired))
			return
		}

		alg := req.Algorithm
		name := req.Name
		escrowAddress := req.EscrowAddress
		hashTxWithdrawal := req.HashTx
		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]

		// Create encrypted storage using server's storage
		stor, err := storage.NewEncryptedStorage(s.stor, s.storagePass)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToCreateStorage, err))
			return
		}

		net, err := network.NewClient(s.env.Communication, myid, another, s.logger.With("component", "network"), s.Conn)
		if err != nil {
			s.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrNetworkSetupFailed, err))
			return
		}

		// send incomplete signature
		switch alg {
		case "ecdsa":
			// getting config and presign
			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), name+"/"+escrowAddress+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetConfig, err))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToUnmarshalConfig, err))
				return
			}

			presign := mpccmp.EmptyPreSign()
			data, err = stor.Get(context.Background(), name+"/"+escrowAddress+"/presign-ecdsa") // Fixed key
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetPresign, err))
				return
			}
			if err := cbor.Unmarshal(data, presign); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToUnmarshalPresign, err))
				return
			}

			// getting incomplete signature our withrawal transaction
			pl := pool.NewPool(0)
			defer pl.TearDown()

			hashB, err := hex.DecodeString(hashTxWithdrawal)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidHashFormat, err))
				return
			}

			incsig, err := mpccmp.CMPPreSignOnlineInc(config, presign, hashB, pl)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToCreateIncSig, err))
				return
			}

			incsigHex, err := mpccmp.MsgToHex(incsig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToConvertSigToHex, err))
				return
			}

			tx := struct {
				IncSig string `json:"inc_sig"`
				HashTx string `json:"hash_tx"`
			}{
				IncSig: incsigHex,
				HashTx: hashTxWithdrawal,
			}

			// send incsig and hash of the withdrawal transaction
			msg := &protocol.Message{}
			msg.Data, err = json.Marshal(tx)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToMarshalMessage, err))
				return
			}
			net.Send(msg)

			response := SendWithdrawalTxResponse{
				Status:  "sent",
				Message: "Incomplete signature sent successfully",
			}
			respondOk(w, response)

		case "frost":
			// TODO: Implementation for FROST
			respondError(w, http.StatusNotImplemented, errors.New(ErrFrostNotImplemented))
			return

		default:
			respondError(w, http.StatusBadRequest, errors.New(ErrUnknownAlgorithm))
			return
		}
	}
}

// Command accept the own withdrawal transaction with our incomplete signature
func (s *Server) acceptWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AcceptWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidRequestBody, err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.MyID == "" || req.Another == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrAlgNameEscrowRequired))
			return
		}

		alg := req.Algorithm
		name := req.Name
		address := req.EscrowAddress
		myid := strings.ReplaceAll(req.MyID, "-", "")[:32]
		another := strings.ReplaceAll(req.Another, "-", "")[:32]

		// Create encrypted storage using server's storage
		pass := "default_pass" // This should come from server config
		stor, err := storage.NewEncryptedStorage(s.stor, pass)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToCreateStorage, err))
			return
		}

		net, err := network.NewClient(s.env.Communication, myid, another, s.logger.With("component", "network"), s.Conn)
		if err != nil {
			s.logger.Error("Failed to setup network", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrNetworkSetupFailed, err))
			return
		}

		// accept incomplete signature and sign it
		switch alg {
		case "ecdsa":
			msg := <-net.Next()

			tx := struct {
				IncSig string `json:"inc_sig"`
				HashTx string `json:"hash_tx"`
			}{}

			if err := json.Unmarshal(msg.Data, &tx); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToUnmarshalMsg, err))
				return
			}

			// getting config and presign
			config := mpccmp.EmptyConfig()
			data, err := stor.Get(context.Background(), name+"/"+address+"/conf-ecdsa")
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetConfig, err))
				return
			}
			if err := cbor.Unmarshal(data, config); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToUnmarshalConfig, err))
				return
			}

			presign := mpccmp.EmptyPreSign()
			data, err = stor.Get(context.Background(), name+"/"+address+"/presign-ecdsa") // Fixed key
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetPresign, err))
				return
			}
			if err := cbor.Unmarshal(data, presign); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToUnmarshalPresign, err))
				return
			}

			// getting another complete signature of the withdrawal transaction
			hashB, err := hex.DecodeString(tx.HashTx)
			if err != nil {
				respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidHashFormat, err))
				return
			}

			incsig, err := mpccmp.HexToMsg(tx.IncSig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToConvertHexToMsg, err))
				return
			}

			pl := pool.NewPool(0)
			defer pl.TearDown()

			sig, err := mpccmp.CMPPreSignOnlineCoSign(config, presign, hashB, incsig, pl)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToCompleteSig, err))
				return
			}

			sigEthereum, err := mpccmp.GetSigByte(sig)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGetSigBytes, err))
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
			_ = msg // TODO: Implement FROST logic
			respondError(w, http.StatusNotImplemented, errors.New(ErrFrostNotImplemented))
			return

		default:
			respondError(w, http.StatusBadRequest, errors.New(ErrUnknownAlgorithm))
			return
		}
	}
}

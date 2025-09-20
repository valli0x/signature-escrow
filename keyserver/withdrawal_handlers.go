package keyserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/network/redis"
	"github.com/valli0x/signature-escrow/mpc/mpccmp"
	"github.com/valli0x/signature-escrow/storage"
)

// Store for messages exchange (if needed for future functionality)
var withdrawalMessages = struct {
	sync.RWMutex
	messages map[string]*protocol.Message
}{messages: make(map[string]*protocol.Message)}

// Command send the own withdrawal transaction with our incomplete signature
func (s *Server) sendWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.HashTx == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("alg, name, escrow_address and hash_tx are required"))
			return
		}

		alg := req.Algorithm
		name := req.Name
		escrowAddress := req.EscrowAddress
		hashTxWithdrawal := req.HashTx

		// ids setup
		myid, err := uuid.GenerateUUID()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate UUID: %v", err))
			return
		}
		myid = strings.ReplaceAll(myid, "-", "")[:32]

		// another of participant ID - in server context, we use a default or from request
		another := "counterparty_id" // This would need to be provided or configured

		// Create encrypted storage using server's storage
		pass := "default_pass" // This should come from server config
		stor, err := storage.NewEncryptedStorage(s.stor, pass)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create encrypted storage: %v", err))
			return
		}

		// network setup
		net, err := redis.NewRedisNet(s.env.Communication, myid, another, s.logger.Named("network"))
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to setup network: %v", err))
			return
		}

		// Store network connection for later use (if needed)
		// connKey := fmt.Sprintf("%s:%s", myid, escrowAddress)
		// networkConnections.Lock()
		// networkConnections.conns[connKey] = net
		// networkConnections.Unlock()

		// send incomplete signature
		switch alg {
		case "ecdsa":
			// getting config and presign
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
			data, err = stor.Get(context.Background(), name+"/"+escrowAddress+"/presign-ecdsa") // Fixed key
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get presign: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, presign); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal presign: %v", err))
				return
			}

			// getting incomplete signature our withrawal transaction
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

			// send incsig and hash of the withdrawal transaction
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
			// TODO: Implementation for FROST
			respondError(w, http.StatusNotImplemented, errors.New("FROST algorithm not implemented yet"))
			return

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}

// Command accept the own withdrawal transaction with our incomplete signature  
func (s *Server) acceptWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AcceptWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("alg, name and escrow_address are required"))
			return
		}

		alg := req.Algorithm
		name := req.Name
		address := req.EscrowAddress

		// ids setup
		myid, err := uuid.GenerateUUID()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate UUID: %v", err))
			return
		}
		myid = strings.ReplaceAll(myid, "-", "")[:32]

		// another of participant ID
		another := "counterparty_id" // This would need to be provided or configured

		// Create encrypted storage using server's storage
		pass := "default_pass" // This should come from server config
		stor, err := storage.NewEncryptedStorage(s.stor, pass)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create encrypted storage: %v", err))
			return
		}

		// network setup
		net, err := redis.NewRedisNet(s.env.Communication, myid, another, s.logger.Named("network"))
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to setup network: %v", err))
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
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal message: %v", err))
				return
			}

			// getting config and presign
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
			data, err = stor.Get(context.Background(), name+"/"+address+"/presign-ecdsa") // Fixed key
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to get presign: %v", err))
				return
			}
			if err := cbor.Unmarshal(data, presign); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal presign: %v", err))
				return
			}

			// getting another complete signature of the withdrawal transaction
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
				Status:           "completed",
				CompleteSignature: completeSignature,
				Message:          "Another complete signature of the withdrawal transaction",
			}
			respondOk(w, response)

		case "frost":
			msg := <-net.Next()
			_ = msg // TODO: Implement FROST logic
			respondError(w, http.StatusNotImplemented, errors.New("FROST algorithm not implemented yet"))
			return

		default:
			respondError(w, http.StatusBadRequest, errors.New("unknown alg(frost or ecdsa)"))
			return
		}
	}
}
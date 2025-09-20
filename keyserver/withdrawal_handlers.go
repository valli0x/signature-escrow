package keyserver

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/valli0x/signature-escrow/stages/mpc/mpccmp"
)

// Store for withdrawal messages
type WithdrawalMessageStore struct {
	mu       sync.RWMutex
	messages map[string]WithdrawalMessageData // key: counterpartyID:escrowAddress
}

type WithdrawalMessageData struct {
	IncSig      string    `json:"inc_sig"`
	HashTx      string    `json:"hash_tx"`
	SenderID    string    `json:"sender_id"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
}

var withdrawalMsgStore = &WithdrawalMessageStore{
	messages: make(map[string]WithdrawalMessageData),
}

func (s *Server) sendWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.HashTx == "" || req.CounterpartyID == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("algorithm, name, escrow_address, hash_tx and counterparty_id are required"))
			return
		}

		response, err := s.processSendWithdrawalTx(req)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to send withdrawal tx: %v", err))
			return
		}

		respondOk(w, response)
	}
}

func (s *Server) acceptWithdrawalTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AcceptWithdrawalTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Algorithm == "" || req.Name == "" || req.EscrowAddress == "" || req.CounterpartyID == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("algorithm, name, escrow_address and counterparty_id are required"))
			return
		}

		response, err := s.processAcceptWithdrawalTx(req)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to accept withdrawal tx: %v", err))
			return
		}

		respondOk(w, response)
	}
}

func (s *Server) processSendWithdrawalTx(req SendWithdrawalTxRequest) (SendWithdrawalTxResponse, error) {
	response := SendWithdrawalTxResponse{
		Status: "processing",
		HashTx: req.HashTx,
	}

	switch req.Algorithm {
	case "ecdsa":
		incSig, err := s.createECDSAIncompleteSignature(req.Name, req.EscrowAddress, req.HashTx)
		if err != nil {
			response.Status = "error"
			response.Message = fmt.Sprintf("Failed to create incomplete signature: %v", err)
			return response, err
		}

		// Store the incomplete signature for counterparty to retrieve
		key := fmt.Sprintf("%s:%s", req.CounterpartyID, req.EscrowAddress)
		withdrawalMsgStore.mu.Lock()
		withdrawalMsgStore.messages[key] = WithdrawalMessageData{
			IncSig:    incSig,
			HashTx:    req.HashTx,
			SenderID:  "sender", // In production, this would be the actual sender ID
			Timestamp: time.Now(),
			Status:    "available",
		}
		withdrawalMsgStore.mu.Unlock()

		response.Status = "sent"
		response.IncSig = incSig
		response.Message = "Incomplete signature sent successfully"

		s.logger.Info("Withdrawal transaction sent", 
			"algorithm", req.Algorithm,
			"name", req.Name,
			"escrow_address", req.EscrowAddress,
			"hash_tx", req.HashTx,
			"counterparty_id", req.CounterpartyID)

	case "frost":
		// TODO: Implement FROST incomplete signature
		response.Status = "error"
		response.Message = "FROST algorithm not implemented yet"
		return response, fmt.Errorf("FROST algorithm not implemented")

	default:
		response.Status = "error"
		response.Message = fmt.Sprintf("Unknown algorithm: %s", req.Algorithm)
		return response, fmt.Errorf("unknown algorithm: %s", req.Algorithm)
	}

	return response, nil
}

func (s *Server) processAcceptWithdrawalTx(req AcceptWithdrawalTxRequest) (AcceptWithdrawalTxResponse, error) {
	response := AcceptWithdrawalTxResponse{
		Status: "waiting",
	}

	// Check if withdrawal message from counterparty is available
	key := fmt.Sprintf("%s:%s", "sender", req.EscrowAddress) // In production, use actual sender ID
	withdrawalMsgStore.mu.RLock()
	withdrawalMsg, exists := withdrawalMsgStore.messages[key]
	withdrawalMsgStore.mu.RUnlock()

	if !exists {
		response.Status = "not_available"
		response.Message = "Withdrawal transaction from counterparty not available"
		return response, nil
	}

	switch req.Algorithm {
	case "ecdsa":
		completeSig, err := s.completeECDSASignature(req.Name, req.EscrowAddress, withdrawalMsg.HashTx, withdrawalMsg.IncSig)
		if err != nil {
			response.Status = "error"
			response.Message = fmt.Sprintf("Failed to complete signature: %v", err)
			return response, err
		}

		response.Status = "completed"
		response.CompleteSignature = completeSig
		response.HashTx = withdrawalMsg.HashTx
		response.Message = "Withdrawal transaction completed successfully"

		s.logger.Info("Withdrawal transaction accepted and completed", 
			"algorithm", req.Algorithm,
			"name", req.Name,
			"escrow_address", req.EscrowAddress,
			"hash_tx", withdrawalMsg.HashTx)

		// Clean up stored message
		withdrawalMsgStore.mu.Lock()
		delete(withdrawalMsgStore.messages, key)
		withdrawalMsgStore.mu.Unlock()

	case "frost":
		// TODO: Implement FROST signature completion
		response.Status = "error"
		response.Message = "FROST algorithm not implemented yet"
		return response, fmt.Errorf("FROST algorithm not implemented")

	default:
		response.Status = "error"
		response.Message = fmt.Sprintf("Unknown algorithm: %s", req.Algorithm)
		return response, fmt.Errorf("unknown algorithm: %s", req.Algorithm)
	}

	return response, nil
}

func (s *Server) createECDSAIncompleteSignature(name, escrowAddress, hashTx string) (string, error) {
	// Load config from storage
	config := mpccmp.EmptyConfig()
	configKey := fmt.Sprintf("%s/%s/conf-ecdsa", name, escrowAddress)
	
	// In production, you would load from actual storage
	// For now, simulate loading config
	s.logger.Debug("Loading ECDSA config", "key", configKey)
	
	// Decode hash
	hashB, err := hex.DecodeString(hashTx)
	if err != nil {
		return "", fmt.Errorf("invalid hash format: %v", err)
	}

	// Load presign (in production, load from storage)
	presign := mpccmp.EmptyPreSign()
	presignKey := fmt.Sprintf("%s/%s/presign-ecdsa", name, escrowAddress)
	s.logger.Debug("Loading ECDSA presign", "key", presignKey)

	// Create incomplete signature using thread pool
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// In production, this would use actual loaded config and presign
	// For now, simulate the process
	incsig, err := s.simulateECDSAIncompleteSignature(config, presign, hashB, pl)
	if err != nil {
		return "", fmt.Errorf("failed to create incomplete signature: %v", err)
	}

	// Convert to hex
	incsigHex, err := mpccmp.MsgToHex(incsig)
	if err != nil {
		return "", fmt.Errorf("failed to convert signature to hex: %v", err)
	}

	return incsigHex, nil
}

func (s *Server) completeECDSASignature(name, escrowAddress, hashTx, incSigHex string) (string, error) {
	// Load config from storage
	config := mpccmp.EmptyConfig()
	configKey := fmt.Sprintf("%s/%s/conf-ecdsa", name, escrowAddress)
	s.logger.Debug("Loading ECDSA config", "key", configKey)

	// Load presign from storage
	presign := mpccmp.EmptyPreSign()
	presignKey := fmt.Sprintf("%s/%s/presign-ecdsa", name, escrowAddress)
	s.logger.Debug("Loading ECDSA presign", "key", presignKey)

	// Decode hash
	hashB, err := hex.DecodeString(hashTx)
	if err != nil {
		return "", fmt.Errorf("invalid hash format: %v", err)
	}

	// Convert incomplete signature from hex
	incsig, err := mpccmp.HexToMsg(incSigHex)
	if err != nil {
		return "", fmt.Errorf("failed to convert hex to message: %v", err)
	}

	// Create thread pool
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Complete the signature (in production, use actual config and presign)
	sig, err := s.simulateECDSACompleteSignature(config, presign, hashB, incsig, pl)
	if err != nil {
		return "", fmt.Errorf("failed to complete signature: %v", err)
	}

	// Get signature bytes for Ethereum format
	// In production, sig would be actual signature type, here we simulate
	sigBytes, ok := sig.([]byte)
	if !ok {
		return "", fmt.Errorf("invalid signature type")
	}

	return hex.EncodeToString(sigBytes), nil
}

// Simulation functions (in production, these would use actual MPC operations)
func (s *Server) simulateECDSAIncompleteSignature(config interface{}, presign interface{}, hash []byte, pl *pool.Pool) (*protocol.Message, error) {
	// Simulate incomplete signature creation
	// In production: return mpccmp.CMPPreSignOnlineInc(config, presign, hash, pl)
	
	// Create a mock protocol message
	mockData := fmt.Sprintf("inc_sig:%x:%d", hash, time.Now().Unix())
	msg := &protocol.Message{
		Data: []byte(mockData),
	}
	
	return msg, nil
}

func (s *Server) simulateECDSACompleteSignature(config interface{}, presign interface{}, hash []byte, incSig *protocol.Message, pl *pool.Pool) (interface{}, error) {
	// Simulate signature completion
	// In production: return mpccmp.CMPPreSignOnlineCoSign(config, presign, hash, incSig, pl)
	
	// Create a mock signature
	mockSig := fmt.Sprintf("complete_sig:%x:%s:%d", hash, string(incSig.Data), time.Now().Unix())
	return []byte(mockSig), nil
}
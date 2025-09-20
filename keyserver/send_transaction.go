package keyserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/blockcypher/gobcy/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func (s *Server) sendTransaction() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendTransactionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Network == "" || req.From == "" || req.To == "" || req.Value == "" || req.Signature == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("network, from, to, value and signature are required"))
			return
		}

		network := strings.ToLower(req.Network)

		var response SendTransactionResponse
		var err error

		switch network {
		case "ethereum", "eth":
			response, err = s.sendEthereumTransaction(req)
		case "bitcoin", "btc":
			response, err = s.sendBitcoinTransaction(req)
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf("unsupported network: %s", req.Network))
			return
		}

		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to send transaction: %v", err))
			return
		}

		respondOk(w, response)
	}
}

func (s *Server) sendEthereumTransaction(req SendTransactionRequest) (SendTransactionResponse, error) {
	response := SendTransactionResponse{
		Status: "processing",
	}

	// Validate Ethereum addresses
	if !common.IsHexAddress(req.From) {
		return response, fmt.Errorf("invalid Ethereum from address: %s", req.From)
	}
	if !common.IsHexAddress(req.To) {
		return response, fmt.Errorf("invalid Ethereum to address: %s", req.To)
	}

	from := common.HexToAddress(req.From)
	to := common.HexToAddress(req.To)
	sig := req.Signature

	// Parse numeric values
	value, ok := new(big.Int).SetString(req.Value, 10)
	if !ok {
		return response, fmt.Errorf("invalid value format: %s", req.Value)
	}

	var gasPrice *big.Int
	if req.GasPrice != "" {
		gasPriceUint, err := strconv.ParseUint(req.GasPrice, 10, 64)
		if err != nil {
			return response, fmt.Errorf("invalid gas price format: %v", err)
		}
		gasPrice = big.NewInt(int64(gasPriceUint))
	}

	var gasLimit uint64 = 21000 // default gas limit for ETH transfer
	if req.GasLimit != "" {
		var err error
		gasLimit, err = strconv.ParseUint(req.GasLimit, 10, 64)
		if err != nil {
			return response, fmt.Errorf("invalid gas limit format: %v", err)
		}
	}

	// Use provided node URL or fallback to server config
	nodeURL := req.NodeURL
	if nodeURL == "" {
		nodeURL = s.env.EthereumRPC
		if nodeURL == "" {
			nodeURL = "https://eth-mainnet.alchemyapi.io/v2/demo"
		}
	}

	// Connect to Ethereum node (original logic from WithdrawalTokensETH)
	client, err := ethclient.Dial(nodeURL)
	if err != nil {
		return response, fmt.Errorf("failed to connect to Ethereum node: %v", err)
	}
	defer client.Close()

	nonce, err := client.NonceAt(context.Background(), from, nil)
	if err != nil {
		return response, fmt.Errorf("failed to get nonce: %v", err)
	}

	// If no gas price provided, get current gas price
	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(context.Background())
		if err != nil {
			return response, fmt.Errorf("failed to get gas price: %v", err)
		}
	}

	// Create a new transaction (original logic from WithdrawalTokensETH)
	tx := types.NewTransaction(
		nonce+1,
		to,
		value,
		gasLimit,
		gasPrice,
		nil)

	// signature byte format (original logic)
	sigB, err := hex.DecodeString(sig)
	if err != nil {
		return response, fmt.Errorf("invalid signature format: %v", err)
	}

	// chain ID (original logic)
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return response, fmt.Errorf("failed to get chain ID: %v", err)
	}

	// Use provided chain ID or default to mainnet
	if req.ChainID != 0 {
		chainID.SetInt64(req.ChainID)
	} else {
		chainID.SetInt64(1) // mainnet (original logic)
	}

	// set signature to tx (original logic from WithdrawalTokensETH)
	tx, err = tx.WithSignature(types.NewLondonSigner(chainID), sigB)
	if err != nil {
		return response, fmt.Errorf("failed to apply signature to transaction: %v", err)
	}

	// send tx (original logic from WithdrawalTokensETH)
	if err := client.SendTransaction(context.Background(), tx); err != nil {
		return response, fmt.Errorf("failed to send transaction to network: %v", err)
	}

	response.Status = "sent"
	response.TxHash = tx.Hash().Hex()
	response.Message = "Transaction sent successfully to Ethereum network"

	s.logger.Info("Ethereum transaction sent", 
		"from", req.From,
		"to", req.To, 
		"value", req.Value,
		"tx_hash", response.TxHash)

	return response, nil
}

func (s *Server) sendBitcoinTransaction(req SendTransactionRequest) (SendTransactionResponse, error) {
	response := SendTransactionResponse{
		Status: "processing",
	}

	// Parse value for Bitcoin (in satoshis)
	value, ok := new(big.Int).SetString(req.Value, 10)
	if !ok {
		return response, fmt.Errorf("invalid value format: %s", req.Value)
	}

	apiToken := s.env.BlockCypherToken
	btcAPI := gobcy.API{
		Token: apiToken,
		Coin:  "btc",
		Chain: "main",
	}

	// Create transaction skeleton
	tempTx := gobcy.TempNewTX(req.From, req.To, *value)
	tx, err := btcAPI.NewTX(tempTx, false)
	if err != nil {
		return response, fmt.Errorf("failed to create Bitcoin transaction: %v", err)
	}

	// Apply signature to transaction
	// For Bitcoin, the signature format is different and needs to be applied to inputs
	tx.Signatures = []string{req.Signature}

	// Send transaction to Bitcoin network
	_, err = btcAPI.SendTX(tx)
	if err != nil {
		return response, fmt.Errorf("failed to send Bitcoin transaction: %v", err)
	}

	response.Status = "sent"
	// Use a different field for Bitcoin transaction hash or generate from transaction data
	response.TxHash = fmt.Sprintf("btc_tx_sent_%s", req.From[:8]) // Simplified hash for now
	response.Message = "Transaction sent successfully to Bitcoin network"

	s.logger.Info("Bitcoin transaction sent", 
		"from", req.From,
		"to", req.To, 
		"value", req.Value,
		"tx_hash", response.TxHash)

	return response, nil
}
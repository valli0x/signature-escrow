package keyserver

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

	"github.com/blockcypher/gobcy/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type TxHashRequest struct {
	Network  string `json:"network"`
	From     string `json:"from"`
	To       string `json:"to"`
	Amount   int64  `json:"amount"`
	GasLimit int64  `json:"gas_limit,omitempty"`
	ChainID  int64  `json:"chain_id,omitempty"`
}

type TxHashResponse struct {
	Network string `json:"network"`
	Hash    string `json:"hash"`
	TxData  string `json:"tx_data,omitempty"`
}

func (s *Server) createTxHash() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TxHashRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrInvalidRequestBody, err))
			return
		}

		if req.Network == "" || req.From == "" || req.To == "" || req.Amount <= 0 {
			respondError(w, http.StatusBadRequest, errors.New(ErrNetworkFromToAmountRequired))
			return
		}

		network := strings.ToLower(req.Network)

		var response TxHashResponse
		var err error

		switch network {
		case "ethereum", "eth":
			response, err = s.createEthereumTxHash(req)
		case "bitcoin", "btc":
			response, err = s.createBitcoinTxHash(req)
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf(ErrUnsupportedNetwork, req.Network))
			return
		}

		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToCreateTxHash, err))
			return
		}

		respondOk(w, response)
	}
}

func (s *Server) createEthereumTxHash(req TxHashRequest) (TxHashResponse, error) {
	response := TxHashResponse{
		Network: req.Network,
	}

	if !common.IsHexAddress(req.From) {
		return response, fmt.Errorf("invalid Ethereum from address: %s", req.From)
	}

	if !common.IsHexAddress(req.To) {
		return response, fmt.Errorf("invalid Ethereum to address: %s", req.To)
	}

	rpcURL := s.env.EthereumRPC
	if rpcURL == "" {
		rpcURL = "https://eth-mainnet.alchemyapi.io/v2/demo"
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return response, fmt.Errorf("failed to connect to Ethereum client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	chainID := req.ChainID
	if chainID == 0 {
		chainID = 1 // mainnet by default
	}

	gasLimit := req.GasLimit
	if gasLimit == 0 {
		gasLimit = 21000 // standard ETH transfer
	}

	// Get nonce
	fromAddr := common.HexToAddress(req.From)
	nonce, err := client.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return response, fmt.Errorf("failed to get nonce: %v", err)
	}

	// Get gas price
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return response, fmt.Errorf("failed to get gas price: %v", err)
	}

	// Create transaction
	toAddr := common.HexToAddress(req.To)
	value := big.NewInt(req.Amount)

	tx := types.NewTransaction(
		nonce,
		toAddr,
		value,
		uint64(gasLimit),
		gasPrice,
		nil, // data
	)

	// Create signer and get hash
	signer := types.NewLondonSigner(big.NewInt(chainID))
	hash := signer.Hash(tx)

	response.Hash = hex.EncodeToString(hash.Bytes())

	// Serialize transaction data for reference
	txData, err := tx.MarshalBinary()
	if err != nil {
		s.logger.Warn("Failed to marshal transaction data", "error", err)
	} else {
		response.TxData = hex.EncodeToString(txData)
	}

	return response, nil
}

func (s *Server) createBitcoinTxHash(req TxHashRequest) (TxHashResponse, error) {
	response := TxHashResponse{
		Network: req.Network,
	}

	apiToken := s.env.BlockCypherToken
	btcAPI := gobcy.API{
		Token: apiToken,
		Coin:  "btc",
		Chain: "main",
	}

	// Create new transaction template
	tx, err := btcAPI.NewTX(gobcy.TempNewTX(req.From, req.To, *big.NewInt(req.Amount)), true)
	if err != nil {
		return response, fmt.Errorf("failed to create Bitcoin transaction: %v", err)
	}

	// Get hash to sign
	if len(tx.ToSign) > 0 {
		// Decode the first hash that needs to be signed
		hash, err := hex.DecodeString(tx.ToSign[0])
		if err != nil {
			return response, fmt.Errorf("failed to decode Bitcoin transaction hash: %v", err)
		}

		response.Hash = hex.EncodeToString(hash)
		// Store the hash from BlockCypher as reference
		response.TxData = tx.ToSign[0]
	} else {
		return response, fmt.Errorf("no hash to sign in Bitcoin transaction")
	}

	return response, nil
}

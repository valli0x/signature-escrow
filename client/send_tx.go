package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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

type SendTransactionRequest struct {
	Network   string `json:"network"`
	From      string `json:"from"`
	To        string `json:"to"`
	Value     string `json:"value"`
	GasPrice  string `json:"gas_price,omitempty"`
	GasLimit  string `json:"gas_limit,omitempty"`
	Signature string `json:"signature"`
	ChainID   int64  `json:"chain_id,omitempty"`
	NodeURL   string `json:"node_url,omitempty"`
}

type SendTransactionResponse struct {
	Status  string `json:"status"`
	TxHash  string `json:"tx_hash"`
	Message string `json:"message"`
}

func (c *Client) sendTransaction() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendTransactionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}

		if req.Network == "" || req.From == "" || req.To == "" || req.Value == "" || req.Signature == "" {
			respondError(w, http.StatusBadRequest, errors.New("network, from, to, value and signature are required"))
			return
		}

		network := strings.ToLower(req.Network)

		var response SendTransactionResponse
		var err error

		switch network {
		case "ethereum", "eth":
			response, err = c.sendEthereumTransaction(req)
		case "bitcoin", "btc":
			response, err = c.sendBitcoinTransaction(req)
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

func (c *Client) sendEthereumTransaction(req SendTransactionRequest) (SendTransactionResponse, error) {
	response := SendTransactionResponse{
		Status: "processing",
	}

	if !common.IsHexAddress(req.From) {
		return response, fmt.Errorf("invalid Ethereum from address: %s", req.From)
	}
	if !common.IsHexAddress(req.To) {
		return response, fmt.Errorf("invalid Ethereum to address: %s", req.To)
	}

	from := common.HexToAddress(req.From)
	to := common.HexToAddress(req.To)

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

	var gasLimit uint64 = 21000
	if req.GasLimit != "" {
		var err error
		gasLimit, err = strconv.ParseUint(req.GasLimit, 10, 64)
		if err != nil {
			return response, fmt.Errorf("invalid gas limit format: %v", err)
		}
	}

	nodeURL := req.NodeURL
	if nodeURL == "" {
		nodeURL = c.env.EthereumRPC
		if nodeURL == "" {
			nodeURL = "https://eth-mainnet.alchemyapi.io/v2/demo"
		}
	}

	ethClient, err := ethclient.Dial(nodeURL)
	if err != nil {
		return response, fmt.Errorf("failed to connect to Ethereum node: %v", err)
	}
	defer ethClient.Close()

	nonce, err := ethClient.NonceAt(context.Background(), from, nil)
	if err != nil {
		return response, fmt.Errorf("failed to get nonce: %v", err)
	}

	if gasPrice == nil {
		gasPrice, err = ethClient.SuggestGasPrice(context.Background())
		if err != nil {
			return response, fmt.Errorf("failed to get gas price: %v", err)
		}
	}

	tx := types.NewTransaction(nonce+1, to, value, gasLimit, gasPrice, nil)

	sigB, err := hex.DecodeString(req.Signature)
	if err != nil {
		return response, fmt.Errorf("invalid signature format: %v", err)
	}

	chainID, err := ethClient.NetworkID(context.Background())
	if err != nil {
		return response, fmt.Errorf("failed to get chain ID: %v", err)
	}

	if req.ChainID != 0 {
		chainID.SetInt64(req.ChainID)
	} else {
		chainID.SetInt64(1)
	}

	tx, err = tx.WithSignature(types.NewLondonSigner(chainID), sigB)
	if err != nil {
		return response, fmt.Errorf("failed to apply signature to transaction: %v", err)
	}

	if err := ethClient.SendTransaction(context.Background(), tx); err != nil {
		return response, fmt.Errorf("failed to send transaction to network: %v", err)
	}

	response.Status = "sent"
	response.TxHash = tx.Hash().Hex()
	response.Message = "Transaction sent successfully to Ethereum network"

	c.logger.Info("Ethereum transaction sent",
		"from", req.From,
		"to", req.To,
		"value", req.Value,
		"tx_hash", response.TxHash)

	return response, nil
}

func (c *Client) sendBitcoinTransaction(req SendTransactionRequest) (SendTransactionResponse, error) {
	response := SendTransactionResponse{
		Status: "processing",
	}

	value, ok := new(big.Int).SetString(req.Value, 10)
	if !ok {
		return response, fmt.Errorf("invalid value format: %s", req.Value)
	}

	apiToken := c.env.BlockCypherToken
	btcAPI := gobcy.API{
		Token: apiToken,
		Coin:  "btc",
		Chain: "main",
	}

	tempTx := gobcy.TempNewTX(req.From, req.To, *value)
	tx, err := btcAPI.NewTX(tempTx, false)
	if err != nil {
		return response, fmt.Errorf("failed to create Bitcoin transaction: %v", err)
	}

	tx.Signatures = []string{req.Signature}

	_, err = btcAPI.SendTX(tx)
	if err != nil {
		return response, fmt.Errorf("failed to send Bitcoin transaction: %v", err)
	}

	response.Status = "sent"
	response.TxHash = fmt.Sprintf("btc_tx_sent_%s", req.From[:8])
	response.Message = "Transaction sent successfully to Bitcoin network"

	c.logger.Info("Bitcoin transaction sent",
		"from", req.From,
		"to", req.To,
		"value", req.Value,
		"tx_hash", response.TxHash)

	return response, nil
}

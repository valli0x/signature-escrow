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

func (c *Client) createTxHash() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TxHashRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
			return
		}

		if req.Network == "" || req.From == "" || req.To == "" || req.Amount <= 0 {
			respondError(w, http.StatusBadRequest, errors.New("network, from, to and amount are required"))
			return
		}

		network := strings.ToLower(req.Network)

		var response TxHashResponse
		var err error

		switch network {
		case "ethereum", "eth":
			response, err = c.createEthereumTxHash(req)
		case "bitcoin", "btc":
			response, err = c.createBitcoinTxHash(req)
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf("unsupported network: %s", req.Network))
			return
		}

		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to create tx hash: %v", err))
			return
		}

		respondOk(w, response)
	}
}

func (c *Client) createEthereumTxHash(req TxHashRequest) (TxHashResponse, error) {
	response := TxHashResponse{
		Network: req.Network,
	}

	if !common.IsHexAddress(req.From) {
		return response, fmt.Errorf("invalid Ethereum from address: %s", req.From)
	}
	if !common.IsHexAddress(req.To) {
		return response, fmt.Errorf("invalid Ethereum to address: %s", req.To)
	}

	rpcURL := c.env.EthereumRPC
	if rpcURL == "" {
		rpcURL = "https://eth-mainnet.alchemyapi.io/v2/demo"
	}

	ethClient, err := ethclient.Dial(rpcURL)
	if err != nil {
		return response, fmt.Errorf("failed to connect to Ethereum client: %v", err)
	}
	defer ethClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	chainID := req.ChainID
	if chainID == 0 {
		chainID = 1
	}

	gasLimit := req.GasLimit
	if gasLimit == 0 {
		gasLimit = 21000
	}

	fromAddr := common.HexToAddress(req.From)
	nonce, err := ethClient.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return response, fmt.Errorf("failed to get nonce: %v", err)
	}

	gasPrice, err := ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return response, fmt.Errorf("failed to get gas price: %v", err)
	}

	toAddr := common.HexToAddress(req.To)
	value := big.NewInt(req.Amount)

	tx := types.NewTransaction(nonce, toAddr, value, uint64(gasLimit), gasPrice, nil)

	signer := types.NewLondonSigner(big.NewInt(chainID))
	hash := signer.Hash(tx)

	response.Hash = hex.EncodeToString(hash.Bytes())

	txData, err := tx.MarshalBinary()
	if err != nil {
		c.logger.Warn("Failed to marshal transaction data", "error", err)
	} else {
		response.TxData = hex.EncodeToString(txData)
	}

	return response, nil
}

func (c *Client) createBitcoinTxHash(req TxHashRequest) (TxHashResponse, error) {
	response := TxHashResponse{
		Network: req.Network,
	}

	apiToken := c.env.BlockCypherToken
	btcAPI := gobcy.API{
		Token: apiToken,
		Coin:  "btc",
		Chain: "main",
	}

	tx, err := btcAPI.NewTX(gobcy.TempNewTX(req.From, req.To, *big.NewInt(req.Amount)), true)
	if err != nil {
		return response, fmt.Errorf("failed to create Bitcoin transaction: %v", err)
	}

	if len(tx.ToSign) > 0 {
		hash, err := hex.DecodeString(tx.ToSign[0])
		if err != nil {
			return response, fmt.Errorf("failed to decode Bitcoin transaction hash: %v", err)
		}
		response.Hash = hex.EncodeToString(hash)
		response.TxData = tx.ToSign[0]
	} else {
		return response, fmt.Errorf("no hash to sign in Bitcoin transaction")
	}

	return response, nil
}

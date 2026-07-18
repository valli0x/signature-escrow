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
	// Token, when set (Ethereum only), makes this an ERC-20 transfer(To, Amount)
	// to the token CONTRACT instead of a native ETH send. Amount is in the
	// token's base units (e.g. USDT has 6 decimals).
	Token string `json:"token,omitempty"`
}

type TxHashResponse struct {
	Network string `json:"network"`
	Hash    string `json:"hash"`
	TxData  string `json:"tx_data,omitempty"`
}

// createTxHash builds an unsigned transaction and returns its signing hash.
//
// @Summary      Create transaction hash
// @Description  Build an unsigned transaction for the given network and return the hash to be signed (and raw tx data where available).
// @Tags         tx
// @Accept       json
// @Produce      json
// @Param        body  body      TxHashRequest  true  "Transaction parameters"
// @Success      200   {object}  TxHashResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/tx/hash [post]
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
		rpcURL = "https://ethereum-rpc.publicnode.com"
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
	var data []byte

	// ERC-20 transfer: send 0 ETH to the token contract with transfer() calldata.
	if req.Token != "" {
		if !common.IsHexAddress(req.Token) {
			return response, fmt.Errorf("invalid token contract address: %s", req.Token)
		}
		data = erc20TransferData(toAddr, value)
		toAddr = common.HexToAddress(req.Token)
		value = big.NewInt(0)
		if req.GasLimit == 0 {
			gasLimit = 65000
		}
	}

	tx := types.NewTransaction(nonce, toAddr, value, uint64(gasLimit), gasPrice, data)

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

type TxDecodeRequest struct {
	Network string `json:"network"`
	TxData  string `json:"tx_data"`
}

// decodeTx returns the authoritative fields of an unsigned tx_data so the
// acceptor can SEE what they are about to co-sign (instead of trusting the
// initiator's display fields).
//
//	@Summary	Decode unsigned tx_data
//	@Tags		tx
//	@Accept		json
//	@Produce	json
//	@Param		body	body		TxDecodeRequest	true	"network + tx_data"
//	@Success	200		{object}	map[string]interface{}
//	@Router		/v1/tx/decode [post]
func (c *Client) decodeTx() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TxDecodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request"))
			return
		}
		if req.TxData == "" {
			respondError(w, http.StatusBadRequest, errors.New("tx_data is required"))
			return
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(req.TxData, "0x"))
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid tx_data hex"))
			return
		}
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("decode tx_data: %v", err))
			return
		}
		to := ""
		if tx.To() != nil {
			to = tx.To().Hex()
		}
		out := map[string]any{
			"to":        to,
			"value":     tx.Value().String(),
			"nonce":     tx.Nonce(),
			"gas":       tx.Gas(),
			"gas_price": tx.GasPrice().String(),
			"is_erc20":  false,
		}
		// If this is an ERC-20 transfer, show the REAL token recipient/amount
		// (from calldata) — not the contract address in `to`. The acceptor must
		// verify these, never the sender's display fields.
		if rTo, amount, ok := decodeERC20Transfer(tx.Data()); ok {
			out["is_erc20"] = true
			out["token"] = to     // the contract we call
			out["to"] = rTo.Hex() // the real recipient
			out["value"] = amount.String()
		}
		respondOk(w, out)
	}
}

type GasPriceResponse struct {
	Network  string `json:"network"`
	GasPrice string `json:"gas_price"` // wei
}

// gasPrice returns the current suggested gas price (wei) for Ethereum, so the
// app can reserve gas when computing a "Max" native-ETH amount.
//
// @Summary      Suggested gas price
// @Tags         tx
// @Produce      json
// @Param        network  query  string  false  "eth (default)"
// @Success      200      {object}  GasPriceResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /v1/tx/gas-price [get]
func (c *Client) gasPrice() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rpcURL := c.env.EthereumRPC
		if rpcURL == "" {
			rpcURL = "https://ethereum-rpc.publicnode.com"
		}
		ec, err := ethclient.Dial(rpcURL)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("rpc dial: %w", err))
			return
		}
		defer ec.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		gp, err := ec.SuggestGasPrice(ctx)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("gas price: %w", err))
			return
		}
		respondOk(w, GasPriceResponse{Network: "eth", GasPrice: gp.String()})
	}
}

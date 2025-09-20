package keyserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blockcypher/gobcy/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func (s *Server) checkBalance() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req BalanceCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Network == "" || req.Address == "" || req.Expected <= 0 {
			respondError(w, http.StatusBadRequest, fmt.Errorf("network, address and expected amount are required"))
			return
		}

		network := strings.ToLower(req.Network)
		
		var response BalanceCheckResponse
		var err error

		switch network {
		case "ethereum", "eth":
			response, err = s.checkEthereumBalance(req)
		case "bitcoin", "btc":
			response, err = s.checkBitcoinBalance(req)
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf("unsupported network: %s", req.Network))
			return
		}

		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to check balance: %v", err))
			return
		}

		respondOk(w, response)
	}
}

func (s *Server) checkEthereumBalance(req BalanceCheckRequest) (BalanceCheckResponse, error) {
	response := BalanceCheckResponse{
		Network:  req.Network,
		Address:  req.Address,
		Expected: req.Expected,
	}

	if !common.IsHexAddress(req.Address) {
		return response, fmt.Errorf("invalid Ethereum address: %s", req.Address)
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

	addr := common.HexToAddress(req.Address)
	balance, err := client.BalanceAt(ctx, addr, nil)
	if err != nil {
		return response, fmt.Errorf("failed to get balance: %v", err)
	}

	balanceWei := balance.Int64()
	response.Balance = balanceWei
	response.IsSufficient = balanceWei >= req.Expected

	return response, nil
}

func (s *Server) checkBitcoinBalance(req BalanceCheckRequest) (BalanceCheckResponse, error) {
	response := BalanceCheckResponse{
		Network:  req.Network,
		Address:  req.Address,
		Expected: req.Expected,
	}

	_, err := btcutil.DecodeAddress(req.Address, nil)
	if err != nil {
		return response, fmt.Errorf("invalid Bitcoin address: %s", req.Address)
	}

	apiToken := s.env.BlockCypherToken
	btcAPI := gobcy.API{
		Token: apiToken,
		Coin:  "btc",
		Chain: "main",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	var wallet gobcy.Addr
	var balanceErr error

	go func() {
		wallet, balanceErr = btcAPI.GetAddrBal(req.Address, nil)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return response, fmt.Errorf("timeout getting Bitcoin balance")
	case <-done:
		if balanceErr != nil {
			return response, fmt.Errorf("failed to get Bitcoin balance: %v", balanceErr)
		}
	}

	balanceSatoshi := wallet.Balance.Int64()
	response.Balance = balanceSatoshi
	response.IsSufficient = balanceSatoshi >= req.Expected

	return response, nil
}

func (s *Server) waitForBalance() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req BalanceWaitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %v", err))
			return
		}

		if req.Network == "" || req.Address == "" || req.Expected <= 0 {
			respondError(w, http.StatusBadRequest, fmt.Errorf("network, address and expected amount are required"))
			return
		}

		if req.TimeoutSec <= 0 {
			req.TimeoutSec = 300 // default 5 minutes
		}

		network := strings.ToLower(req.Network)
		
		response := BalanceWaitResponse{
			Network:  req.Network,
			Address:  req.Address,
			Expected: req.Expected,
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutSec)*time.Second)
		defer cancel()

		switch network {
		case "ethereum", "eth":
			result, err := s.waitForEthereumBalance(ctx, req)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to wait for Ethereum balance: %v", err))
				return
			}
			response = result
		case "bitcoin", "btc":
			result, err := s.waitForBitcoinBalance(ctx, req)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to wait for Bitcoin balance: %v", err))
				return
			}
			response = result
		default:
			respondError(w, http.StatusBadRequest, fmt.Errorf("unsupported network: %s", req.Network))
			return
		}

		respondOk(w, response)
	}
}

func (s *Server) waitForEthereumBalance(ctx context.Context, req BalanceWaitRequest) (BalanceWaitResponse, error) {
	response := BalanceWaitResponse{
		Network:  req.Network,
		Address:  req.Address,
		Expected: req.Expected,
	}

	if !common.IsHexAddress(req.Address) {
		return response, fmt.Errorf("invalid Ethereum address: %s", req.Address)
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

	addr := common.HexToAddress(req.Address)
	ticker := time.NewTicker(12 * time.Second) // Ethereum block time
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			response.TimedOut = true
			return response, nil
		case <-ticker.C:
			balance, err := client.BalanceAt(ctx, addr, nil)
			if err != nil {
				s.logger.Error("Failed to get Ethereum balance", "error", err)
				continue
			}

			balanceWei := balance.Int64()
			response.Balance = balanceWei

			if balanceWei >= req.Expected {
				response.IsSufficient = true
				return response, nil
			}
		}
	}
}

func (s *Server) waitForBitcoinBalance(ctx context.Context, req BalanceWaitRequest) (BalanceWaitResponse, error) {
	response := BalanceWaitResponse{
		Network:  req.Network,
		Address:  req.Address,
		Expected: req.Expected,
	}

	_, err := btcutil.DecodeAddress(req.Address, nil)
	if err != nil {
		return response, fmt.Errorf("invalid Bitcoin address: %s", req.Address)
	}

	apiToken := s.env.BlockCypherToken
	btcAPI := gobcy.API{
		Token: apiToken,
		Coin:  "btc",
		Chain: "main",
	}

	ticker := time.NewTicker(10 * time.Minute) // Bitcoin block time
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			response.TimedOut = true
			return response, nil
		case <-ticker.C:
			wallet, err := btcAPI.GetAddrBal(req.Address, nil)
			if err != nil {
				s.logger.Error("Failed to get Bitcoin balance", "error", err)
				continue
			}

			balanceSatoshi := wallet.Balance.Int64()
			response.Balance = balanceSatoshi

			if balanceSatoshi >= req.Expected {
				response.IsSufficient = true
				return response, nil
			}
		}
	}
}
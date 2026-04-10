package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/valli0x/signature-escrow/auth"
)

const tokenTTL = 24 * time.Hour

type NonceRequest struct {
	Address string `json:"address"`
}

type NonceResponse struct {
	Nonce   string `json:"nonce"`
	Message string `json:"message"`
}

type LoginRequest struct {
	Address   string `json:"address"`
	Signature string `json:"signature"`
	Nonce     string `json:"nonce"`
}

type LoginResponse struct {
	Token   string `json:"token"`
	Address string `json:"address"`
}

func (s *Server) authNonce() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req NonceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Address == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("address is required"))
			return
		}

		nonce, err := s.nonceStore.Generate(req.Address)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate nonce: %w", err))
			return
		}

		message := auth.GenerateNonce(req.Address, nonce)

		respondOk(w, NonceResponse{
			Nonce:   nonce,
			Message: message,
		})
	}
}

func (s *Server) authLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Address == "" || req.Signature == "" || req.Nonce == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("address, signature and nonce are required"))
			return
		}

		if !s.nonceStore.Verify(req.Address, req.Nonce) {
			respondError(w, http.StatusUnauthorized, fmt.Errorf("invalid or expired nonce"))
			return
		}

		message := auth.GenerateNonce(req.Address, req.Nonce)

		address, err := auth.VerifySignature(req.Address, message, req.Signature)
		if err != nil {
			s.logger.Error("signature verification failed", "error", err)
			respondError(w, http.StatusUnauthorized, fmt.Errorf("signature verification failed"))
			return
		}

		token, err := auth.GenerateToken(address, s.jwtSecret, tokenTTL)
		if err != nil {
			s.logger.Error("failed to generate token", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate token"))
			return
		}

		s.logger.Info("user authenticated", "address", address.Hex())

		respondOk(w, LoginResponse{
			Token:   token,
			Address: address.Hex(),
		})
	}
}

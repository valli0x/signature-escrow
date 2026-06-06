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

// authNonce issues a one-time nonce for an ETH address to sign.
//
// @Summary      Request a login nonce
// @Description  Returns a nonce and an EIP-191 message for the given ETH address. The client signs the message and submits it to /v1/auth/login.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      NonceRequest  true  "ETH address"
// @Success      200   {object}  NonceResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/auth/nonce [post]
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

// authLogin verifies a signed nonce and issues a JWT.
//
// @Summary      Login with a signed nonce
// @Description  Verifies the EIP-191 signature over the nonce message and returns a JWT (valid 24h) on success.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      LoginRequest  true  "Address, signature and nonce"
// @Success      200   {object}  LoginResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/auth/login [post]
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

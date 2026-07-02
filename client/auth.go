package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/valli0x/signature-escrow/auth"
)

const (
	clientTokenTTL = 24 * time.Hour
	ownerKey       = "client/owner"
)

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

type IdentityResponse struct {
	Address      string `json:"address"`
	HasKeys      bool   `json:"has_keys"`
	Bound        bool   `json:"bound"`
	AuthRequired bool   `json:"auth_required"`
}

func normAddr(a string) string {
	a = strings.TrimSpace(strings.ToLower(a))
	if a != "" && !strings.HasPrefix(a, "0x") {
		a = "0x" + a
	}
	return a
}

func (c *Client) keyIdentity() string {
	for _, net := range []string{"eth", "btc"} {
		for i := 1; i <= 100; i++ {
			key := fmt.Sprintf("accounts/%s/%d/meta", net, i)
			data, err := c.stor.Get(context.Background(), key)
			if err != nil || data == nil {
				continue
			}
			var meta AccountMeta
			if err := cbor.Unmarshal(data, &meta); err != nil {
				continue
			}
			if id := normAddr(meta.PairMyID); id != "" {
				return id
			}
		}
	}
	return ""
}

func (c *Client) storedOwner() string {
	data, err := c.stor.Get(context.Background(), ownerKey)
	if err != nil || data == nil {
		return ""
	}
	return normAddr(string(data))
}

func (c *Client) owner() string {
	if id := c.keyIdentity(); id != "" {
		return id
	}
	return c.storedOwner()
}

func (c *Client) bindOwner(addr string) error {
	return c.stor.Put(context.Background(), ownerKey, []byte(normAddr(addr)))
}

// authNonce issues a one-time nonce for an ETH address to sign.
//
// @Summary      Request a client login nonce
// @Description  Returns a nonce and EIP-191 message for the address to sign, then submit to /v1/auth/login.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      NonceRequest  true  "ETH address"
// @Success      200   {object}  NonceResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Router       /v1/auth/nonce [post]
func (c *Client) authNonce() http.HandlerFunc {
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
		nonce, err := c.nonceStore.Generate(req.Address)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate nonce: %w", err))
			return
		}
		respondOk(w, NonceResponse{Nonce: nonce, Message: auth.GenerateNonce(req.Address, nonce)})
	}
}

// authLogin verifies a signed nonce, enforces the client's owner binding and
// issues a JWT scoped to THIS client.
//
// @Summary      Login to this client
// @Description  Verifies the EIP-191 signature and returns a client JWT (24h). If the client already holds keys (or was bound before), only that owner address is accepted; a fresh client binds to the first successful login.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      LoginRequest  true  "Address, signature and nonce"
// @Success      200   {object}  LoginResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      403   {object}  ErrorResponse
// @Router       /v1/auth/login [post]
func (c *Client) authLogin() http.HandlerFunc {
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
		if !c.nonceStore.Verify(req.Address, req.Nonce) {
			respondError(w, http.StatusUnauthorized, fmt.Errorf("invalid or expired nonce"))
			return
		}
		message := auth.GenerateNonce(req.Address, req.Nonce)
		address, err := auth.VerifySignature(req.Address, message, req.Signature)
		if err != nil {
			respondError(w, http.StatusUnauthorized, fmt.Errorf("signature verification failed"))
			return
		}
		signer := normAddr(address.Hex())

		if own := c.owner(); own != "" {
			if signer != own {
				respondError(w, http.StatusForbidden,
					fmt.Errorf("this client is bound to %s; sign in with that account", own))
				return
			}
		} else {
			if err := c.bindOwner(signer); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to bind owner: %w", err))
				return
			}
			c.logger.Info("client bound to owner", "address", signer)
		}

		token, err := auth.GenerateToken(address, c.jwtSecret, clientTokenTTL)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate token"))
			return
		}
		respondOk(w, LoginResponse{Token: token, Address: address.Hex()})
	}
}

// identity reports which address this client belongs to. Public so the app can
// warn the user before attempting a login it knows will be rejected.
//
// @Summary      Client identity
// @Description  Returns the owner address this client is bound to (from its key material or a prior binding), whether it holds keys, and whether it is bound.
// @Tags         auth
// @Produce      json
// @Success      200  {object}  IdentityResponse
// @Router       /v1/identity [get]
func (c *Client) identity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := c.keyIdentity()
		own := c.owner()
		respondOk(w, IdentityResponse{Address: own, HasKeys: id != "", Bound: own != "", AuthRequired: c.authEnabled})
	}
}

func (c *Client) ownerGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		own := c.owner()
		if own != "" {
			caller := normAddr(auth.AddressFromContext(r.Context()))
			if caller != own {
				respondError(w, http.StatusForbidden,
					fmt.Errorf("this client is bound to %s", own))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

package client

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/valli0x/signature-escrow/mpc/mpccmp"
)

type SigEthRequest struct {
	Signature string `json:"signature"`
}

type SigEthResponse struct {
	Signature string `json:"signature"`
}

// sigToEthereum converts a CMP-native ECDSA signature ([33B R][32B S], the
// format stored/validated by the server escrow) into the 65-byte Ethereum
// r||s||v form required by tx broadcast.
//
// @Summary      Convert a CMP signature to Ethereum format
// @Description  Input: hex of the 65-byte CMP-native signature (33-byte compressed R point + 32-byte S scalar), as released by the escrow. Output: hex of the 65-byte Ethereum signature (r||s||v, low-s) for use with /v1/tx/send.
// @Tags         withdrawal
// @Accept       json
// @Produce      json
// @Param        body  body      SigEthRequest  true  "CMP signature hex"
// @Success      200   {object}  SigEthResponse
// @Failure      400   {object}  ErrorResponse
// @Router       /v1/sig/ethereum [post]
func (c *Client) sigToEthereum() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SigEthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		raw, err := hex.DecodeString(req.Signature)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid signature hex: %w", err))
			return
		}
		if len(raw) != 65 {
			respondError(w, http.StatusBadRequest, fmt.Errorf("expected 65-byte CMP signature (33B R + 32B S), got %d", len(raw)))
			return
		}
		sig, err := mpccmp.FromSigByte(raw)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("failed to parse CMP signature: %w", err))
			return
		}
		ethSig, err := mpccmp.SigEthereum(sig)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to convert: %w", err))
			return
		}
		respondOk(w, SigEthResponse{Signature: hex.EncodeToString(ethSig)})
	}
}

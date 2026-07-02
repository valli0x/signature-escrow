package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidAddress   = errors.New("invalid ethereum address")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidToken     = errors.New("invalid token")
)

type Claims struct {
	Address string `json:"address"`
	jwt.RegisteredClaims
}

func VerifySignature(address, message, signature string) (common.Address, error) {
	if !common.IsHexAddress(address) {
		return common.Address{}, ErrInvalidAddress
	}

	sig, err := hexutil.Decode(signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("decode signature: %w", err)
	}

	if len(sig) != 65 {
		return common.Address{}, ErrInvalidSignature
	}

	if sig[64] >= 27 {
		sig[64] -= 27
	}

	msgHash := accounts.TextHash([]byte(message))

	pubKey, err := crypto.SigToPub(msgHash, sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover public key: %w", err)
	}

	recovered := crypto.PubkeyToAddress(*pubKey)
	expected := common.HexToAddress(address)

	if !strings.EqualFold(recovered.Hex(), expected.Hex()) {
		return common.Address{}, ErrInvalidSignature
	}

	return recovered, nil
}

func GenerateToken(address common.Address, secret []byte, ttl time.Duration) (string, error) {
	claims := Claims{
		Address: strings.ToLower(address.Hex()),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func ValidateToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func GenerateNonce(address string, nonce string) string {
	return fmt.Sprintf("Sign in to MPC Oven\nAddress: %s\nNonce: %s", address, nonce)
}

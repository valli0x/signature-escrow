package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const AddressKey contextKey = "eth_address"

func Middleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				http.Error(w, `{"errors":["missing authorization header"]}`, http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(header, "Bearer ")
			if token == header {
				http.Error(w, `{"errors":["invalid authorization format"]}`, http.StatusUnauthorized)
				return
			}

			claims, err := ValidateToken(token, secret)
			if err != nil {
				http.Error(w, `{"errors":["invalid or expired token"]}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), AddressKey, claims.Address)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AddressFromContext(ctx context.Context) string {
	addr, _ := ctx.Value(AddressKey).(string)
	return addr
}

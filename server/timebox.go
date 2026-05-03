package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/valli0x/signature-escrow/auth"
	"github.com/valli0x/signature-escrow/storage"
	"github.com/valli0x/signature-escrow/validation"
)

// timeboxDelay — после этого срока с момента POST подпись становится
// доступной по GET. Идея: если общий счёт пополнен только одной стороной
// и вторая не пополняет, через час можно вывести средства.
const timeboxDelay = time.Hour

type timeboxEntry struct {
	Alg       validation.SignaturesType
	Pub       []byte
	Hash      []byte
	Sig       []byte
	PairID    string // pair, к которой привязана запись (для авторизации)
	CreatedAt time.Time
}

// pairContains возвращает true, если addr — initiator или partner пары.
func pairContains(p *Pair, addr string) bool {
	return strings.EqualFold(p.Initiator, addr) || strings.EqualFold(p.Partner, addr)
}

// authorizeTimeboxAccess загружает пару по pairID и проверяет, что
// текущий вызывающий (из JWT-контекста) — один из её участников.
func (s *Server) authorizeTimeboxAccess(r *http.Request, pairID string) (*Pair, error) {
	if pairID == "" {
		return nil, errors.New("pair_id is required")
	}
	pair, err := loadPair(s.stor, pairID)
	if err != nil {
		return nil, fmt.Errorf("storage error")
	}
	if pair == nil {
		return nil, errors.New("pair not found")
	}
	caller := auth.AddressFromContext(r.Context())
	if !pairContains(pair, caller) {
		return nil, errors.New("caller is not a member of this pair")
	}
	return pair, nil
}

func timeboxKey(pub []byte) string {
	return "timebox/" + hex.EncodeToString(pub)
}

func getTimebox(stor storage.Storage, pub []byte) (*timeboxEntry, error) {
	data, err := stor.Get(context.Background(), timeboxKey(pub))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	e := &timeboxEntry{}
	if err := cbor.Unmarshal(data, e); err != nil {
		return nil, err
	}
	return e, nil
}

func putTimebox(stor storage.Storage, e *timeboxEntry) error {
	data, err := cbor.Marshal(e)
	if err != nil {
		return err
	}
	return stor.Put(context.Background(), timeboxKey(e.Pub), data)
}

func deleteTimebox(stor storage.Storage, pub []byte) error {
	return stor.Delete(context.Background(), timeboxKey(pub))
}

// validatePub применяет правила длины/префикса pub в зависимости от алгоритма.
func validatePub(alg validation.SignaturesType, pub []byte) error {
	switch alg {
	case validation.ECDSA:
		if len(pub) != pubLenECDSA {
			return fmt.Errorf("ecdsa pub must be %d bytes (compressed secp256k1), got %d", pubLenECDSA, len(pub))
		}
		if pub[0] != 0x02 && pub[0] != 0x03 {
			return fmt.Errorf("ecdsa pub must start with 0x02 or 0x03, got 0x%02x", pub[0])
		}
	case validation.Frost:
		if len(pub) != pubLenFrost {
			return fmt.Errorf("frost pub must be %d bytes (x-only), got %d", pubLenFrost, len(pub))
		}
	default:
		return fmt.Errorf("unknown alg: %s", alg)
	}
	return nil
}

// ---------- POST /v1/timebox ----------

type TimeboxPostRequest struct {
	Alg    string `json:"alg"`
	PairID string `json:"pair_id"` // обязателен: ограничивает, кто может POST/GET
	Pub    string `json:"pub"`
	Hash   string `json:"hash"`
	Sig    string `json:"sig"`
}

func parseTimeboxPost(r *http.Request) (*timeboxEntry, error) {
	var req TimeboxPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("error parsing JSON")
	}
	if req.Alg == "" || req.PairID == "" || req.Pub == "" || req.Hash == "" || req.Sig == "" {
		return nil, fmt.Errorf("alg, pair_id, pub, hash and sig are required")
	}
	alg := validation.SignaturesType(req.Alg)
	if alg != validation.ECDSA && alg != validation.Frost {
		return nil, fmt.Errorf("alg must be %q or %q", validation.ECDSA, validation.Frost)
	}
	pub, err := hex.DecodeString(req.Pub)
	if err != nil {
		return nil, fmt.Errorf("invalid pub hex: %w", err)
	}
	if err := validatePub(alg, pub); err != nil {
		return nil, err
	}
	hash, err := hex.DecodeString(req.Hash)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(hash) != hashLen {
		return nil, fmt.Errorf("hash must be %d bytes, got %d", hashLen, len(hash))
	}
	sig, err := hex.DecodeString(req.Sig)
	if err != nil {
		return nil, fmt.Errorf("invalid sig hex: %w", err)
	}
	if len(sig) > maxSigLen {
		return nil, fmt.Errorf("sig too long (max %d bytes), got %d", maxSigLen, len(sig))
	}
	return &timeboxEntry{
		Alg:       alg,
		Pub:       pub,
		Hash:      hash,
		Sig:       sig,
		PairID:    req.PairID,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (s *Server) timeboxPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, err := parseTimeboxPost(r)
		if err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}

		// Авторизация: только участники пары могут класть запись.
		if _, err := s.authorizeTimeboxAccess(r, e.PairID); err != nil {
			respondError(w, http.StatusForbidden, err)
			return
		}

		// Проверяем подпись на стадии POST — не сохраняем заведомо мусорные записи.
		ok, err := validation.Validate(e.Alg, e.Pub, e.Hash, e.Sig)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("signature validation: %w", err))
			return
		}
		if !ok {
			respondError(w, http.StatusBadRequest, errors.New("signature does not verify"))
			return
		}

		if err := putTimebox(s.stor, e); err != nil {
			s.logger.Error("timebox put", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}

		s.logger.Info("timebox stored", "pair_id", e.PairID, "pub", hex.EncodeToString(e.Pub), "available_at", e.CreatedAt.Add(timeboxDelay))

		respondOk(w, map[string]any{
			"status":       "stored",
			"available_at": e.CreatedAt.Add(timeboxDelay).Format(time.RFC3339),
		})
	}
}

// ---------- GET /v1/timebox?pub=&hash= ----------

func (s *Server) timeboxGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubHex := r.URL.Query().Get("pub")
		hashHex := r.URL.Query().Get("hash")
		if pubHex == "" || hashHex == "" {
			respondError(w, http.StatusBadRequest, errors.New("pub and hash query params are required"))
			return
		}

		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid pub hex: %w", err))
			return
		}
		hash, err := hex.DecodeString(hashHex)
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid hash hex: %w", err))
			return
		}
		if len(hash) != hashLen {
			respondError(w, http.StatusBadRequest, fmt.Errorf("hash must be %d bytes, got %d", hashLen, len(hash)))
			return
		}

		entry, err := getTimebox(s.stor, pub)
		if err != nil {
			s.logger.Error("timebox get", "error", err)
			respondError(w, http.StatusInternalServerError, fmt.Errorf("storage error"))
			return
		}
		if entry == nil {
			respondOk(w, map[string]any{
				"has_signature": false,
				"valid":         false,
			})
			return
		}

		// Авторизация: только участники пары, к которой привязана запись,
		// могут читать timebox-подпись.
		if _, err := s.authorizeTimeboxAccess(r, entry.PairID); err != nil {
			respondError(w, http.StatusForbidden, err)
			return
		}

		// Проверяем, что хранимая подпись валидна для (entry.Pub, переданный hash, entry.Sig).
		valid, _ := validation.Validate(entry.Alg, entry.Pub, hash, entry.Sig)
		resp := map[string]any{
			"has_signature": true,
			"valid":         valid,
		}
		if !valid {
			respondOk(w, resp)
			return
		}

		availableAt := entry.CreatedAt.Add(timeboxDelay)
		now := time.Now().UTC()
		if now.Before(availableAt) {
			resp["ready"] = false
			resp["available_in_seconds"] = int(availableAt.Sub(now).Seconds())
			resp["available_at"] = availableAt.Format(time.RFC3339)
			respondOk(w, resp)
			return
		}

		// Прошёл час и валидность подтверждена — выдаём подпись.
		resp["ready"] = true
		resp["signature"] = base64.StdEncoding.EncodeToString(entry.Sig)
		respondOk(w, resp)
	}
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/valli0x/signature-escrow/auth"
)

type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]sessionEntry
}

type sessionEntry struct {
	status string
	at     time.Time
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: make(map[string]sessionEntry)}
}

func (r *sessionRegistry) prune() {
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, v := range r.m {
		if v.at.Before(cutoff) {
			delete(r.m, k)
		}
	}
}

func (r *sessionRegistry) claim(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if e, ok := r.m[id]; ok && e.status == "cancelled" {
		return false
	}
	r.m[id] = sessionEntry{status: "claimed", at: time.Now()}
	return true
}

func (r *sessionRegistry) cancel(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if e, ok := r.m[id]; ok && e.status == "claimed" {
		return false
	}
	r.m[id] = sessionEntry{status: "cancelled", at: time.Now()}
	return true
}

type SessionRequest struct {
	SessionID string `json:"session_id"`
}

type SessionResponse struct {
	OK bool `json:"ok"`
}

// sessionClaim lets the partner claim a keygen session before running its half.
//
// @Summary      Claim a keygen session
// @Description  The partner calls this before running its keygen half. ok=true means proceed; ok=false means the initiator already cancelled.
// @Tags         session
// @Accept       json
// @Produce      json
// @Param        body  body      SessionRequest  true  "Session ID"
// @Success      200   {object}  SessionResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Security     BearerAuth
// @Router       /v1/session/claim [post]
func (s *Server) sessionClaim() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := auth.AddressFromContext(r.Context())
		if addr == "" {
			respondError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		var req SessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.SessionID == "" {
			respondError(w, http.StatusBadRequest, errors.New("session_id is required"))
			return
		}
		respondOk(w, map[string]bool{"ok": s.sessions.claim(req.SessionID)})
	}
}

// sessionCancel lets the initiator cancel a keygen session.
//
// @Summary      Cancel a keygen session
// @Description  The initiator calls this to cancel. ok=true means cancelled; ok=false means the partner already claimed (too late to cancel).
// @Tags         session
// @Accept       json
// @Produce      json
// @Param        body  body      SessionRequest  true  "Session ID"
// @Success      200   {object}  SessionResponse
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Security     BearerAuth
// @Router       /v1/session/cancel [post]
func (s *Server) sessionCancel() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := auth.AddressFromContext(r.Context())
		if addr == "" {
			respondError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		var req SessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}
		if req.SessionID == "" {
			respondError(w, http.StatusBadRequest, errors.New("session_id is required"))
			return
		}
		respondOk(w, map[string]bool{"ok": s.sessions.cancel(req.SessionID)})
	}
}

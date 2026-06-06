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

// sessionRegistry is an in-memory, atomic registry that resolves the
// cancel/accept race for keygen sessions. Keygen runs on the clients, but the
// decision of whether the partner proceeds must be made at a single
// serialization point — this server.
//
// Model: the INITIATOR cancels, the PARTNER claims (on accept). Under one
// mutex, exactly one of {cancel, claim} wins when they collide:
//   - claim succeeds unless the session was already cancelled.
//   - cancel succeeds unless the session was already claimed.
type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]sessionEntry
}

type sessionEntry struct {
	status string // "claimed" | "cancelled"
	at     time.Time
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: make(map[string]sessionEntry)}
}

// prune drops entries older than 15 minutes. Caller must hold the lock.
func (r *sessionRegistry) prune() {
	cutoff := time.Now().Add(-15 * time.Minute)
	for k, v := range r.m {
		if v.at.Before(cutoff) {
			delete(r.m, k)
		}
	}
}

// claim returns true if the partner may proceed (session open or already
// claimed). Returns false if the session was cancelled by the initiator.
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

// cancel returns true if the session was cancelled (open or already cancelled).
// Returns false if the partner already claimed it (too late to cancel).
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

// SessionRequest is the body for session claim/cancel: {"session_id":"..."}.
type SessionRequest struct {
	SessionID string `json:"session_id"`
}

// SessionResponse is the result of a session claim/cancel: {"ok":true|false}.
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

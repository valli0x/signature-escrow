package keyserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/go-uuid"
)

func (s *Server) generateIDs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req IDGenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
			return
		}

		if req.Name == "" {
			respondError(w, http.StatusBadRequest, fmt.Errorf("name is required"))
			return
		}

		// Generate my ID
		myid, err := uuid.GenerateUUID()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate my ID: %w", err))
			return
		}
		myid = strings.ReplaceAll(myid, "-", "")[:32]

		// Generate another participant ID
		another, err := uuid.GenerateUUID()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate another ID: %w", err))
			return
		}
		another = strings.ReplaceAll(another, "-", "")[:32]

		response := IDGenerateResponse{
			MyID:    myid,
			Another: another,
		}

		respondOk(w, response)
	}
}

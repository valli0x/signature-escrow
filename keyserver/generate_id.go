package keyserver

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type IDGenerateResponse struct {
	MyID    string `json:"my_id"`
	Another string `json:"another_id"`
}

func (s *Server) generateIDs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate my ID
		myid := strings.ReplaceAll(uuid.New().String(), "-", "")[:32]

		// Generate another participant ID
		another := strings.ReplaceAll(uuid.New().String(), "-", "")[:32]

		response := &IDGenerateResponse{
			MyID:    myid,
			Another: another,
		}

		respondOk(w, response)
	}
}

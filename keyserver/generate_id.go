package keyserver

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/go-uuid"
)

type IDGenerateResponse struct {
	MyID    string `json:"my_id"`
	Another string `json:"another_id"`
}

func (s *Server) generateIDs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Generate my ID
		myid, err := uuid.GenerateUUID()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGenerateMyID, err))
			return
		}
		myid = strings.ReplaceAll(myid, "-", "")[:32]

		// Generate another participant ID
		another, err := uuid.GenerateUUID()
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Errorf(ErrFailedToGenerateAnotherID, err))
			return
		}
		another = strings.ReplaceAll(another, "-", "")[:32]

		response := &IDGenerateResponse{
			MyID:    myid,
			Another: another,
		}

		respondOk(w, response)
	}
}

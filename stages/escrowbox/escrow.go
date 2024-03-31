package escrowbox

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/valli0x/signature-escrow/validation"
)

func (s *server) escrow() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*
			0 stage: parsing data
		*/

		data := map[string]interface{}{}
		_, err := parseJSONRequest(r, w, &data)
		if err == io.EOF {
			data, err = nil, nil
			respondError(w, http.StatusBadRequest, fmt.Errorf("error parsing JSON"))
			return
		}
		if err != nil {
			respondError(w, http.StatusBadRequest, fmt.Errorf("error parsing JSON"))
			return
		}

		fr := &struct {
			Alg, Id, Pub, Hash, Sig string
		}{}

		if err := mapstructure.Decode(data, fr); err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		/*
			1 stage: create flower
		*/

		if validation.Alg(fr.Alg) == "" || fr.Id == "" || fr.Pub == "" || fr.Hash == "" {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		pubB, err := base64.StdEncoding.DecodeString(fr.Pub)
		if err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		hashB, err := base64.StdEncoding.DecodeString(fr.Hash)
		if err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		var sigB []byte
		if fr.Sig != "" {
			sigB, err = base64.StdEncoding.DecodeString(fr.Sig)
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
				return
			}
		}

		flower := &flower{
			ID:   fr.Id,
			Alg:  validation.SignaturesType(fr.Alg),
			Pub:  pubB,
			Hash: hashB,
			Sig:  sigB,
		}

		/*
			2 stage: pollination
		*/

		pollination, err := GetPollination(flower.ID, s.stor)
		if err != nil {
			respondError(w, http.StatusInternalServerError, nil)
			return
		}

		if pollination == nil {
			pollination = NewPollination()

			pollination.AddFlower(flower)
			if err := PutPollination(flower.ID, pollination, s.stor); err != nil {
				respondError(w, http.StatusInternalServerError, nil)
				return
			}
			respondOk(w, nil)
			return
		}

		pollination.AddFlower(flower)
		if err := PutPollination(flower.ID, pollination, s.stor); err != nil {
			respondError(w, http.StatusInternalServerError, nil)
			return
		}

		pollinated, err := pollination.Pollinate()
		if err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		if pollinated {
			if flower := pollination.GetFlower(pubB); flower != nil {
				respondOk(w, map[string]string{
					"signature": base64.StdEncoding.EncodeToString(flower.Sig),
				})
				return
			}
		}

		respondOk(w, nil)
	})
}


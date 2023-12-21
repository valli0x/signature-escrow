package escrowbox

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/valli0x/signature-escrow/validation"
)

type Server struct {
	port string
	stor logical.Storage
}

func NewServer(port string, stor logical.Storage) *Server {
	return &Server{
		port: port,
		stor: stor,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/v1/escrow", s.escrow())

	ln, err := net.Listen("tcp", s.port)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}
	server.Serve(ln)

	return nil
}

func (s *Server) escrow() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, nil)
			return
		}

		// parsing data
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
		fr := &flowerRequest{}
		if err := mapstructure.Decode(data, fr); err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		// 1 stage: create flower
		if fr.Alg == "" || fr.Id == "" || fr.Pub == "" || fr.Hash == "" {
			respondError(w, http.StatusBadRequest, nil)
			return
		}

		flower := &flower{}
		flower.Alg = validation.SignaturesType(fr.Alg)
		flower.ID = fr.Id

		pubB, err := base64.StdEncoding.DecodeString(fr.Pub)
		if err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}
		flower.Pub = pubB

		hashB, err := base64.StdEncoding.DecodeString(fr.Hash)
		if err != nil {
			respondError(w, http.StatusBadRequest, nil)
			return
		}
		flower.Hash = hashB

		if fr.Sig != "" {
			sigB, err := base64.StdEncoding.DecodeString(fr.Sig)
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
				return
			}
			flower.Sig = sigB
		}

		// 2 stage: pollination
		pollination, err := GetPollination(fr.Id, s.stor)
		if err != nil {
			respondError(w, http.StatusInternalServerError, nil)
			return
		}

		if pollination == nil {
			pollination = NewPollination()
			pollination.AddFlower(flower)
			if err := PutPollination(fr.Id, pollination, s.stor); err != nil {
				respondError(w, http.StatusInternalServerError, nil)
				return
			}
			respondOk(w, nil)
			return
		}

		pollination.AddFlower(flower)
		if err := PutPollination(fr.Id, pollination, s.stor); err != nil {
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

type flowerRequest struct {
	Alg, Id, Pub, Hash, Sig string
}

func respondOk(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if body == nil {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.Encode(body)
	}
}

func respondError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	type ErrorResponse struct {
		Errors []string `json:"errors"`
	}
	resp := &ErrorResponse{Errors: make([]string, 0, 1)}
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
	}

	enc := json.NewEncoder(w)
	enc.Encode(resp)
}

func parseJSONRequest(r *http.Request, w http.ResponseWriter, out interface{}) (io.ReadCloser, error) {
	// Limit the maximum number of bytes to MaxRequestSize to protect
	// against an indefinite amount of data being read.
	reader := r.Body
	ctx := r.Context()
	maxRequestSize := ctx.Value("max_request_size")
	if maxRequestSize != nil {
		max, ok := maxRequestSize.(int64)
		if !ok {
			return nil, errors.New("could not parse max_request_size from request context")
		}
		if max > 0 {
			// MaxBytesReader won't do all the internal stuff it must unless it's
			// given a ResponseWriter that implements the internal http interface
			// requestTooLarger.  So we let it have access to the underlying
			// ResponseWriter.
			inw := w
			if myw, ok := inw.(logical.WrappingResponseWriter); ok {
				inw = myw.Wrapped()
			}
			reader = http.MaxBytesReader(inw, r.Body, max)
		}
	}
	var origBody io.ReadWriter
	err := jsonutil.DecodeJSONFromReader(reader, out)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to parse JSON input: %w", err)
	}
	if origBody != nil {
		return io.NopCloser(origBody), err
	}
	return nil, err
}

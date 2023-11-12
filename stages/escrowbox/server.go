package escrowbox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

type Server struct {
	port    string
	stor logical.Storage
}

func NewServer(port string, stor logical.Storage) *Server {
	return &Server{
		port:    port,
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
		switch r.Method {
		case http.MethodGet:
			data := parseQuery(r.URL.Query())
			values := map[string]string{}
			if err := mapstructure.Decode(data, values); err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}

			id, pub := values["id"], values["pub"]

			pollination, err := GetPollination(id, s.stor)
			if err != nil {
				respondError(w, http.StatusNotFound, nil)
			}

			pubB, err := base64.StdEncoding.DecodeString(pub)
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}

			if !pollination.Pollinated {
				respondError(w, http.StatusInternalServerError, fmt.Errorf("invalid"))
			}

			signature := ""
			if bytes.Equal(pollination.Flower1.Pub, pubB) {
				signature = hex.EncodeToString(pollination.Flower2.Sig)
			} else {
				signature = hex.EncodeToString(pollination.Flower1.Sig)
			}

			respondOk(w, map[string]string{
				"signature": signature,
			})
		case http.MethodPost:
			// parsing data
			data := map[string]interface{}{}
			_, err := parseJSONRequest(r, w, &data)
			if err == io.EOF {
				data, err = nil, nil
				respondError(w, http.StatusBadRequest, fmt.Errorf("error parsing JSON"))
			}
			if err != nil {
				status := http.StatusBadRequest
				logical.AdjustErrorStatusCode(&status, err)
				respondError(w, status, fmt.Errorf("error parsing JSON"))
			}

			values := map[string]string{}
			if err := mapstructure.Decode(data, values); err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}

			alg, id, pub, hash, sig := values["alg"], values["id"], values["pub"], values["hash"], values["sig"]

			if alg == "" || id == "" || pub == "" || hash == "" || sig == "" {
				respondError(w, http.StatusBadRequest, nil)
			}

			pubB, err := base64.StdEncoding.DecodeString(pub)
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}
			hashB, err := base64.StdEncoding.DecodeString(hash)
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}
			sigB, err := base64.StdEncoding.DecodeString(sig)
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}

			flower := &flower{ 
				Alg:  SignaturesType(alg),
				ID:   id,
				Pub:  pubB,
				Hash: hashB,
				Sig:  sigB,
			}

			pollination, err := GetPollination(id, s.stor)
			if err != nil {
				respondError(w, http.StatusNotFound, nil)
			}

			pollination.AddFlower(flower)

			pollinated, err := pollination.Pollinate()
			if err != nil {
				respondError(w, http.StatusBadRequest, nil)
			}

			if err := PutPollination(id, pollination, s.stor); err != nil {
				respondError(w, http.StatusInternalServerError, nil)
			}

			if pollinated {
				signature := ""
				if bytes.Equal(pollination.Flower1.Pub, pubB) {
					signature = hex.EncodeToString(pollination.Flower2.Sig)
				} else {
					signature = hex.EncodeToString(pollination.Flower1.Sig)
				}

				respondOk(w, map[string]string{
					"signature": signature,
				})
			}
			respondOk(w, nil)
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
		}
	})
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

func parseQuery(values url.Values) map[string]interface{} {
	data := map[string]interface{}{}
	for k, v := range values {
		// Skip the help key as this is a reserved parameter
		if k == "help" {
			continue
		}

		switch {
		case len(v) == 0:
		case len(v) == 1:
			data[k] = v[0]
		default:
			data[k] = v
		}
	}

	if len(data) > 0 {
		return data
	}
	return nil
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

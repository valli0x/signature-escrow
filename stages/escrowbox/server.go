package escrowbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	timeoutSeconds = 10
	idleTimeout    = 20
	maxHeaderBytes = 1024 * 1024
)

type server struct {
	addr string
	srv  *http.Server
	stor logical.Storage
}

type SrvConfig struct {
	Addr string
	Stor logical.Storage
}

func NewServer(cfg *SrvConfig) *server {
	httpServer := &http.Server{
		MaxHeaderBytes: maxHeaderBytes,
		IdleTimeout:    idleTimeout * time.Second,
		ReadTimeout:    timeoutSeconds * time.Second,
		WriteTimeout:   timeoutSeconds * time.Second,
	}

	s := &server{
		srv:  httpServer,
		addr: cfg.Addr,
		stor: cfg.Stor,
	}

	s.srv.Handler = s.routers()

	return s
}

func (s *server) Run(ctx context.Context) {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Printf("can't listen on %s. server quitting: %v", s.addr, err)
		return
	}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		<-ctx.Done()

		if err := s.srv.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
	}(wg)

	log.Printf("server listening on %s", s.addr)
	if err := s.srv.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		wg.Done()
		log.Printf("unexpected (http.Server).Serve error: %v", err)
	}

	wg.Wait()
	log.Printf("server off")
}

func respondOk(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if body == nil {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(body)
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

	json.NewEncoder(w).Encode(resp)
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

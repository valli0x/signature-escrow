package keyserver

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/valli0x/signature-escrow/config"
	"github.com/valli0x/signature-escrow/storage"
)

const (
	timeoutSeconds = 10
	idleTimeout    = 20
	maxHeaderBytes = 1024 * 1024
)

type Server struct {
	addr   string
	srv    *http.Server
	stor   storage.Storage
	logger hclog.Logger
	env    *config.Env
}

type ServerConfig struct {
	Addr   string
	Stor   storage.Storage
	Logger hclog.Logger
	Env    *config.Env
}

func NewServer(cfg *ServerConfig) *Server {
	httpServer := &http.Server{
		MaxHeaderBytes: maxHeaderBytes,
		IdleTimeout:    idleTimeout * time.Second,
		ReadTimeout:    timeoutSeconds * time.Second,
		WriteTimeout:   timeoutSeconds * time.Second,
	}

	s := &Server{
		srv:    httpServer,
		addr:   cfg.Addr,
		stor:   cfg.Stor,
		logger: cfg.Logger,
		env:    cfg.Env,
	}

	s.srv.Handler = s.routes()

	return s
}

func (s *Server) Run(ctx context.Context) {
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

	log.Printf("key server listening on %s", s.addr)
	if err := s.srv.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		wg.Done()
		log.Printf("unexpected (http.Server).Serve error: %v", err)
	}

	wg.Wait()
	log.Printf("key server off")
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

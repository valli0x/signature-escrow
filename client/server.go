package client

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/valli0x/signature-escrow/config"
	"github.com/valli0x/signature-escrow/storage"
	"google.golang.org/grpc"
)

const (
	ipv4           = "tcp4"
	timeoutSeconds = 300
	idleTimeout    = 300
	maxHeaderBytes = 1024 * 1024
)

type Client struct {
	addr        string
	srv         *http.Server
	stor        storage.Storage
	logger      *slog.Logger
	env         *config.Env
	storagePass string
	Conn        *grpc.ClientConn
}

type ClientConfig struct {
	Addr        string
	Stor        storage.Storage
	Logger      *slog.Logger
	Env         *config.Env
	StoragePass string
	Conn        *grpc.ClientConn
}

func NewClient(cfg *ClientConfig) *Client {
	httpServer := &http.Server{
		MaxHeaderBytes: maxHeaderBytes,
		IdleTimeout:    idleTimeout * time.Second,
		ReadTimeout:    timeoutSeconds * time.Second,
		WriteTimeout:   timeoutSeconds * time.Second,
	}

	c := &Client{
		srv:         httpServer,
		addr:        cfg.Addr,
		stor:        cfg.Stor,
		logger:      cfg.Logger,
		env:         cfg.Env,
		storagePass: cfg.StoragePass,
		Conn:        cfg.Conn,
	}

	c.srv.Handler = c.routes()

	return c
}

func (c *Client) Run(ctx context.Context) {
	listener, err := net.Listen(ipv4, c.addr)
	if err != nil {
		c.logger.Error("can't listen on address, client quitting", "addr", c.addr, "error", err)
		return
	}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		<-ctx.Done()

		if err := c.srv.Shutdown(context.Background()); err != nil {
			c.logger.Error("HTTP server shutdown error", "error", err)
		}
	}(wg)

	c.logger.Info("client server listening", "addr", c.addr)
	if err := c.srv.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		wg.Done()
		c.logger.Error("unexpected HTTP server serve error", "error", err)
	}

	wg.Wait()
	c.logger.Info("client server off")
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

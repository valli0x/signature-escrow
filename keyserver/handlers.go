package keyserver

import "github.com/go-chi/chi"

type KeygenRequest struct {
	Name    string `json:"name"`
	MyID    string `json:"my_id"`
	Another string `json:"another_id"`
}

type KeygenECDSAResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

type KeygenFROSTResponse struct {
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

type IDGenerateResponse struct {
	MyID    string `json:"my_id"`
	Another string `json:"another_id"`
}

type IDGenerateRequest struct {
	Name string `json:"name"`
}

type BalanceCheckRequest struct {
	Network  string `json:"network"`
	Address  string `json:"address"`
	Expected int64  `json:"expected"`
}

type BalanceCheckResponse struct {
	Network     string `json:"network"`
	Address     string `json:"address"`
	Balance     int64  `json:"balance"`
	Expected    int64  `json:"expected"`
	IsSufficient bool  `json:"is_sufficient"`
}

type BalanceWaitRequest struct {
	Network     string `json:"network"`
	Address     string `json:"address"`
	Expected    int64  `json:"expected"`
	TimeoutSec  int    `json:"timeout_sec,omitempty"`
}

type BalanceWaitResponse struct {
	Network      string `json:"network"`
	Address      string `json:"address"`
	Balance      int64  `json:"balance"`
	Expected     int64  `json:"expected"`
	IsSufficient bool   `json:"is_sufficient"`
	TimedOut     bool   `json:"timed_out"`
}

type TxHashRequest struct {
	Network   string `json:"network"`
	From      string `json:"from"`
	To        string `json:"to"`
	Amount    int64  `json:"amount"`
	GasLimit  int64  `json:"gas_limit,omitempty"`
	ChainID   int64  `json:"chain_id,omitempty"`
}

type TxHashResponse struct {
	Network string `json:"network"`
	Hash    string `json:"hash"`
	TxData  string `json:"tx_data,omitempty"`
}




func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Post("/generate-ids", s.generateIDs())
		r.Post("/ecdsa", s.keygenECDSA())
		r.Post("/frost", s.keygenFROST())
		r.Post("/balance/check", s.checkBalance())
		r.Post("/balance/wait", s.waitForBalance())
		r.Post("/tx/hash", s.createTxHash())
	})
	return r
}

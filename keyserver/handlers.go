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

type PartialSignRequest struct {
	SignerID    string `json:"signer_id"`
	CounterpartyID string `json:"counterparty_id"`
	MessageHash string `json:"message_hash"`
	Network     string `json:"network,omitempty"`
}

type PartialSignResponse struct {
	SignerID    string `json:"signer_id"`
	MessageHash string `json:"message_hash"`
	PartialSig  string `json:"partial_signature"`
	Round       int    `json:"round"`
	Status      string `json:"status"`
}

type PartialSignReceiveRequest struct {
	SignerID       string `json:"signer_id"`
	CounterpartyID string `json:"counterparty_id"`
	MessageHash    string `json:"message_hash"`
	Network        string `json:"network,omitempty"`
}

type PartialSignReceiveResponse struct {
	SignerID       string `json:"signer_id"`
	CounterpartyID string `json:"counterparty_id"`
	MessageHash    string `json:"message_hash"`
	PartialSig     string `json:"partial_signature"`
	CompleteSign   string `json:"complete_signature,omitempty"`
	Status         string `json:"status"`
}

type SendWithdrawalTxRequest struct {
	Algorithm      string `json:"algorithm"`
	Name           string `json:"name"`
	EscrowAddress  string `json:"escrow_address"`
	HashTx         string `json:"hash_tx"`
	CounterpartyID string `json:"counterparty_id"`
}

type SendWithdrawalTxResponse struct {
	Status         string `json:"status"`
	IncSig         string `json:"inc_sig"`
	HashTx         string `json:"hash_tx"`
	Message        string `json:"message"`
}

type AcceptWithdrawalTxRequest struct {
	Algorithm      string `json:"algorithm"`
	Name           string `json:"name"`
	EscrowAddress  string `json:"escrow_address"`
	CounterpartyID string `json:"counterparty_id"`
}

type AcceptWithdrawalTxResponse struct {
	Status           string `json:"status"`
	CompleteSignature string `json:"complete_signature"`
	HashTx           string `json:"hash_tx"`
	Message          string `json:"message"`
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
		r.Post("/withdrawal/send", s.sendWithdrawalTx())
		r.Post("/withdrawal/accept", s.acceptWithdrawalTx())
	})
	return r
}

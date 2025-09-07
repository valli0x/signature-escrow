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

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Post("/generate-ids", s.generateIDs())
		r.Post("/ecdsa", s.keygenECDSA())
		r.Post("/frost", s.keygenFROST())
	})
	return r
}

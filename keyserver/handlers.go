package keyserver

import "github.com/go-chi/chi"

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Route("/keygen", func(r chi.Router) {
			r.Post("/generate-ids", s.generateIDs())
			r.Post("/ecdsa", s.keygenECDSA())
			r.Post("/frost", s.keygenFROST())
		})

		r.Route("/balance", func(r chi.Router) {
			r.Post("/check", s.checkBalance())
			r.Post("/wait", s.waitForBalance())
		})

		r.Route("/tx", func(r chi.Router) {
			r.Post("/hash", s.createTxHash())
			r.Post("/send", s.sendTransaction())
		})

		r.Route("/incomplete-signature", func(r chi.Router) {
			r.Post("/send", s.sendWithdrawalTx())
			r.Post("/accept", s.acceptWithdrawalTx())
		})
	})
	return r
}

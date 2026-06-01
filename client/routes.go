package client

import (
	"github.com/go-chi/chi"
	"github.com/rs/cors"
)

func (c *Client) routes() *chi.Mux {
	r := chi.NewRouter()

	Cors := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Accept"},
		AllowCredentials: false,
	})
	r.Use(Cors.Handler)

	r.Route("/v1", func(r chi.Router) {
		r.Route("/keygen", func(r chi.Router) {
			r.Post("/ecdsa", c.keygenECDSA())
			r.Post("/frost", c.keygenFROST())
		})

		r.Route("/accounts", func(r chi.Router) {
			r.Get("/list", c.listAccounts())
			r.Post("/get", c.getAccount())
			r.Post("/delete", c.deleteAccount())
		})

		r.Route("/balance", func(r chi.Router) {
			r.Post("/check", c.checkBalance())
			r.Post("/wait", c.waitForBalance())
		})

		r.Route("/tx", func(r chi.Router) {
			r.Post("/hash", c.createTxHash())
			r.Post("/send", c.sendTransaction())
		})

		r.Route("/incomplete-signature", func(r chi.Router) {
			r.Post("/send", c.sendWithdrawalTx())
			r.Post("/accept", c.acceptWithdrawalTx())
		})
	})

	return r
}

package client

import (
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/valli0x/signature-escrow/apidocs"
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

	// Swagger UI: /swagger/index.html
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

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

		r.Route("/exchanges", func(r chi.Router) {
			r.Get("/list", c.listExchanges())
			r.Post("/create", c.createExchange())
			r.Post("/update", c.updateExchange())
			r.Post("/upsert", c.upsertExchange())
			r.Post("/delete", c.deleteExchange())
		})

		r.Route("/balance", func(r chi.Router) {
			r.Post("/check", c.checkBalance())
			r.Post("/wait", c.waitForBalance())
		})

		r.Route("/tx", func(r chi.Router) {
			r.Post("/hash", c.createTxHash())
			r.Post("/send", c.sendTransaction())
			r.Post("/decode", c.decodeTx())
		})

		r.Route("/aliases", func(r chi.Router) {
			r.Get("/list", c.listAliases())
			r.Post("/set", c.setAlias())
			r.Post("/delete", c.deleteAlias())
		})

		r.Route("/cosign", func(r chi.Router) {
			r.Get("/history", c.listCosignHistory())
			r.Post("/history/clear", c.clearCosignHistory())
			r.Post("/complete", c.completeCosign())
		})

		r.Route("/incomplete-signature", func(r chi.Router) {
			r.Post("/send", c.sendWithdrawalTx())
			r.Post("/accept", c.acceptWithdrawalTx())
		})
	})

	return r
}

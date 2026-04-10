package keyserver

import (
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	"github.com/valli0x/signature-escrow/auth"
)

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()

	// CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Accept"},
		AllowCredentials: false,
	})
	r.Use(c.Handler)

	r.Route("/v1", func(r chi.Router) {
		// Public auth endpoints
		r.Route("/auth", func(r chi.Router) {
			r.Post("/nonce", s.authNonce())
			r.Post("/login", s.authLogin())
		})

		// Protected endpoints
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(s.jwtSecret))

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
	})
	return r
}

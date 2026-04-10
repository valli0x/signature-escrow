package server

import (
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	"github.com/valli0x/signature-escrow/auth"
)

func (s *Server) routes() *chi.Mux {
	r := chi.NewRouter()

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Accept", "Authorization"},
		AllowCredentials: false,
	})
	r.Use(c.Handler)

	r.Route("/v1", func(r chi.Router) {
		// Public: auth
		r.Route("/auth", func(r chi.Router) {
			r.Post("/nonce", s.authNonce())
			r.Post("/login", s.authLogin())
		})

		// Protected
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(s.jwtSecret))

			r.Post("/escrow", s.escrow())
			r.Post("/timebox", s.timebox())
		})
	})

	return r
}

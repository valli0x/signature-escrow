package server

import (
	"github.com/go-chi/chi"
	"github.com/rs/cors"
	httpSwagger "github.com/swaggo/http-swagger"
	"github.com/valli0x/signature-escrow/auth"
	_ "github.com/valli0x/signature-escrow/apidocs"
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

	// Swagger UI: /swagger/index.html
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	r.Route("/v1", func(r chi.Router) {
		// Public: auth
		r.Route("/auth", func(r chi.Router) {
			r.Post("/nonce", s.authNonce())
			r.Post("/login", s.authLogin())
		})

		// Protected
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(s.jwtSecret))

			r.Route("/pair", func(r chi.Router) {
				r.Post("/create", s.pairCreate())
				r.Post("/accept", s.pairAccept())
				r.Get("/pending", s.pairPending())
				r.Post("/delete", s.pairDelete())
			})

			r.Route("/mailbox", func(r chi.Router) {
				r.Post("/send", s.mailboxSend())
				r.Get("/pending", s.mailboxPending())
				r.Post("/ack", s.mailboxAck())
			})

			r.Route("/session", func(r chi.Router) {
				r.Post("/claim", s.sessionClaim())
				r.Post("/cancel", s.sessionCancel())
			})

			r.Post("/escrow", s.escrow())
			r.Post("/escrow/check", s.escrowCheck())

			r.Route("/timebox", func(r chi.Router) {
				r.Post("/", s.timeboxPost())
				r.Get("/", s.timeboxGet())
			})
		})
	})

	return r
}

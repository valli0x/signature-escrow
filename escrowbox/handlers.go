package escrowbox

import "github.com/go-chi/chi"

func (s *server) routers() *chi.Mux {
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Post("/escrow", s.escrow())
		r.Post("/timebox", s.timebox())
	})
	return r
}

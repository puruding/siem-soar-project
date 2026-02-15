package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/siem-soar-platform/services/ml-gateway/internal/config"
)

// New creates a new HTTP router.
func New(predictHandler, modelHandler, healthHandler http.Handler, cfg *config.Config) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(cfg.ClassifyTimeout))

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Routes
	r.Get("/health", healthHandler.ServeHTTP)
	r.Get("/ready", healthHandler.ServeHTTP)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/predict", predictHandler.ServeHTTP)
		r.Get("/models", modelHandler.ServeHTTP)
	})

	return r
}

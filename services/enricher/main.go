package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	serviceName = "enricher"
	defaultPort = "8090"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", readyHandler)
	mux.HandleFunc("POST /api/v1/enrich", enrichHandler)
	mux.HandleFunc("POST /api/v1/enrich/batch", batchEnrichHandler)
	mux.HandleFunc("GET /api/v1/geoip/{ip}", geoipLookupHandler)
	mux.HandleFunc("GET /api/v1/asset/{identifier}", assetLookupHandler)
	mux.HandleFunc("GET /api/v1/user/{identifier}", userLookupHandler)
	mux.HandleFunc("GET /api/v1/threat/{ioc}", threatLookupHandler)
	mux.HandleFunc("GET /api/v1/cache/stats", cacheStatsHandler)
	mux.HandleFunc("POST /api/v1/cache/invalidate", cacheInvalidateHandler)
	mux.HandleFunc("GET /api/v1/stats", statsHandler)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("starting server", "service", serviceName, "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server exited")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"enricher"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready","service":"enricher"}`)
}

func enrichHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"event enriched","enrichments":{}}`)
}

func batchEnrichHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"batch enriched","count":0,"success":0,"failed":0}`)
}

func geoipLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"ip":"","country":"","city":"","asn":"","org":""}`)
}

func assetLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"asset_id":"","hostname":"","ip":[],"owner":"","department":"","criticality":""}`)
}

func userLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"user_id":"","username":"","email":"","department":"","title":"","manager":""}`)
}

func threatLookupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"ioc":"","type":"","threat_type":"","confidence":0,"sources":[],"last_seen":""}`)
}

func cacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"geoip":{"hits":0,"misses":0,"size":0},"asset":{"hits":0,"misses":0,"size":0},"user":{"hits":0,"misses":0,"size":0},"threat":{"hits":0,"misses":0,"size":0}}`)
}

func cacheInvalidateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"cache invalidated"}`)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"events_enriched":0,"enrich_errors":0,"avg_enrich_time_ms":0,"cache_hit_rate":0}`)
}

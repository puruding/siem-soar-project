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

	"github.com/siem-soar-platform/services/gateway/internal/handler"
)

const (
	serviceName = "gateway"
	defaultPort = "8080"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", readyHandler)

	// Alert API routes
	mux.HandleFunc("GET /api/v1/alerts", handler.ListAlertsHandler)
	mux.HandleFunc("POST /api/v1/alerts", handler.CreateAlertHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts", handler.CreateAlertHandler) // CORS preflight

	// Single alert operations
	mux.HandleFunc("GET /api/v1/alerts/{id}", handler.GetAlertHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}", handler.GetAlertHandler)
	mux.HandleFunc("PUT /api/v1/alerts/{id}/status", handler.UpdateAlertStatusHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/status", handler.UpdateAlertStatusHandler)
	mux.HandleFunc("GET /api/v1/alerts/{id}/related", handler.GetRelatedAlertsHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/related", handler.GetRelatedAlertsHandler)

	// Quick Action endpoints for alerts
	mux.HandleFunc("POST /api/v1/alerts/{id}/acknowledge", handler.AcknowledgeAlertHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/acknowledge", handler.AcknowledgeAlertHandler)
	mux.HandleFunc("POST /api/v1/alerts/{id}/close", handler.CloseAlertHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/close", handler.CloseAlertHandler)
	mux.HandleFunc("POST /api/v1/alerts/{id}/create-case", handler.CreateCaseFromAlertHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/create-case", handler.CreateCaseFromAlertHandler)
	mux.HandleFunc("POST /api/v1/alerts/{id}/run-playbook", handler.RunPlaybookOnAlertHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/run-playbook", handler.RunPlaybookOnAlertHandler)

	// Alert comments
	mux.HandleFunc("GET /api/v1/alerts/{id}/comments", handler.GetAlertCommentsHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{id}/comments", handler.GetAlertCommentsHandler)
	mux.HandleFunc("POST /api/v1/alerts/{id}/comments", handler.AddAlertCommentHandler)

	// Case API routes
	mux.HandleFunc("GET /api/v1/cases", handler.ListCasesHandler)
	mux.HandleFunc("POST /api/v1/cases", handler.CreateCaseHandler)
	mux.HandleFunc("OPTIONS /api/v1/cases", handler.CreateCaseHandler)
	mux.HandleFunc("GET /api/v1/cases/{id}", handler.GetCaseHandler)
	mux.HandleFunc("OPTIONS /api/v1/cases/{id}", handler.GetCaseHandler)

	// Playbook API routes
	mux.HandleFunc("GET /api/v1/playbooks", handler.ListPlaybooksHandler)
	mux.HandleFunc("OPTIONS /api/v1/playbooks", handler.ListPlaybooksHandler)
	mux.HandleFunc("POST /api/v1/playbooks/run/{id}", handler.ExecutePlaybookHandler)
	mux.HandleFunc("OPTIONS /api/v1/playbooks/run/{id}", handler.ExecutePlaybookHandler)
	mux.HandleFunc("GET /api/v1/playbooks/{id}", handler.GetPlaybookHandler)
	mux.HandleFunc("OPTIONS /api/v1/playbooks/{id}", handler.GetPlaybookHandler)

	// Playbook execution routes (separate path to avoid conflict)
	mux.HandleFunc("GET /api/v1/executions", handler.ListExecutionsHandler)
	mux.HandleFunc("OPTIONS /api/v1/executions", handler.ListExecutionsHandler)
	mux.HandleFunc("GET /api/v1/executions/{id}", handler.GetExecutionStatusHandler)
	mux.HandleFunc("OPTIONS /api/v1/executions/{id}", handler.GetExecutionStatusHandler)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
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
	fmt.Fprint(w, `{"status":"healthy","service":"gateway"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready","service":"gateway"}`)
}

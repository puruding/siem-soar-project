// Package receiver provides log reception from various sources.
package receiver

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPMessage represents an HTTP-received log message.
type HTTPMessage struct {
	TenantID    string
	SourceType  string
	Timestamp   time.Time
	ContentType string
	Logs        []json.RawMessage
	RawBody     []byte
	Headers     map[string]string
	RemoteAddr  string
	ReceivedAt  time.Time
}

// HTTPReceiverConfig holds HTTP receiver configuration.
type HTTPReceiverConfig struct {
	ListenAddr     string
	TLSEnabled     bool
	TLSCertPath    string
	TLSKeyPath     string
	MaxBodySize    int64
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	APIKeyHeader   string
	APIKeys        map[string]string // api_key -> tenant_id
	RateLimitRPS   int
	RateLimitBurst int
}

// HTTPReceiver receives logs over HTTP/HTTPS.
type HTTPReceiver struct {
	config   HTTPReceiverConfig
	output   chan<- *HTTPMessage
	server   *http.Server
	logger   *slog.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Rate limiting
	rateLimiter *rateLimiter

	// Metrics
	requestsReceived atomic.Uint64
	messagesReceived atomic.Uint64
	bytesReceived    atomic.Uint64
	rateLimited      atomic.Uint64
	errors           atomic.Uint64
}

// NewHTTPReceiver creates a new HTTP receiver.
func NewHTTPReceiver(cfg HTTPReceiverConfig, output chan<- *HTTPMessage, logger *slog.Logger) *HTTPReceiver {
	ctx, cancel := context.WithCancel(context.Background())

	r := &HTTPReceiver{
		config: cfg,
		output: output,
		logger: logger.With("component", "http-receiver"),
		ctx:    ctx,
		cancel: cancel,
	}

	if cfg.RateLimitRPS > 0 {
		r.rateLimiter = newRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)
	}

	return r
}

// Start begins the HTTP receiver.
func (r *HTTPReceiver) Start() error {
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("GET /health", r.healthHandler)
	mux.HandleFunc("GET /ready", r.readyHandler)

	// Ingestion endpoints
	mux.HandleFunc("POST /api/v1/logs", r.handleLogs)
	mux.HandleFunc("POST /api/v1/logs/{source}", r.handleLogsWithSource)
	mux.HandleFunc("POST /api/v1/ingest", r.handleIngest)
	mux.HandleFunc("POST /api/v1/events", r.handleEvents)

	// Bulk ingestion
	mux.HandleFunc("POST /api/v1/bulk", r.handleBulk)

	r.server = &http.Server{
		Addr:         r.config.ListenAddr,
		Handler:      r.middleware(mux),
		ReadTimeout:  r.config.ReadTimeout,
		WriteTimeout: r.config.WriteTimeout,
		IdleTimeout:  120 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return r.ctx },
	}

	if r.config.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(r.config.TLSCertPath, r.config.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificates: %w", err)
		}
		r.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		var err error
		if r.config.TLSEnabled {
			r.logger.Info("starting HTTPS receiver", "addr", r.config.ListenAddr)
			err = r.server.ListenAndServeTLS("", "")
		} else {
			r.logger.Info("starting HTTP receiver", "addr", r.config.ListenAddr)
			err = r.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			r.logger.Error("server error", "error", err)
		}
	}()

	return nil
}

// Stop stops the HTTP receiver.
func (r *HTTPReceiver) Stop() error {
	r.cancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := r.server.Shutdown(shutdownCtx); err != nil {
		return err
	}

	r.wg.Wait()
	return nil
}

// Stats returns receiver statistics.
func (r *HTTPReceiver) Stats() map[string]uint64 {
	return map[string]uint64{
		"requests_received": r.requestsReceived.Load(),
		"messages_received": r.messagesReceived.Load(),
		"bytes_received":    r.bytesReceived.Load(),
		"rate_limited":      r.rateLimited.Load(),
		"errors":            r.errors.Load(),
	}
}

func (r *HTTPReceiver) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Skip middleware for health endpoints
		if req.URL.Path == "/health" || req.URL.Path == "/ready" {
			next.ServeHTTP(w, req)
			return
		}

		// Rate limiting
		if r.rateLimiter != nil && !r.rateLimiter.Allow() {
			r.rateLimited.Add(1)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// API key authentication
		tenantID := r.authenticate(req)
		if tenantID == "" {
			r.errors.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Add tenant ID to context
		ctx := context.WithValue(req.Context(), tenantIDKey, tenantID)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

type contextKey string

const tenantIDKey contextKey = "tenant_id"

func (r *HTTPReceiver) authenticate(req *http.Request) string {
	// Check API key header
	apiKey := req.Header.Get(r.config.APIKeyHeader)
	if apiKey != "" {
		if tenantID, ok := r.config.APIKeys[apiKey]; ok {
			return tenantID
		}
	}

	// Check Authorization header
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if tenantID, ok := r.config.APIKeys[token]; ok {
			return tenantID
		}
	}

	// In development mode, allow without auth
	if len(r.config.APIKeys) == 0 {
		return "default"
	}

	return ""
}

func (r *HTTPReceiver) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy"}`)
}

func (r *HTTPReceiver) readyHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready"}`)
}

func (r *HTTPReceiver) handleLogs(w http.ResponseWriter, req *http.Request) {
	r.processRequest(w, req, "generic")
}

func (r *HTTPReceiver) handleLogsWithSource(w http.ResponseWriter, req *http.Request) {
	source := req.PathValue("source")
	r.processRequest(w, req, source)
}

func (r *HTTPReceiver) handleIngest(w http.ResponseWriter, req *http.Request) {
	r.processRequest(w, req, req.URL.Query().Get("source"))
}

func (r *HTTPReceiver) handleEvents(w http.ResponseWriter, req *http.Request) {
	r.processRequest(w, req, "events")
}

func (r *HTTPReceiver) handleBulk(w http.ResponseWriter, req *http.Request) {
	r.processRequest(w, req, "bulk")
}

func (r *HTTPReceiver) processRequest(w http.ResponseWriter, req *http.Request, sourceType string) {
	r.requestsReceived.Add(1)

	tenantID, _ := req.Context().Value(tenantIDKey).(string)
	if tenantID == "" {
		tenantID = "default"
	}

	// Read and decompress body
	body, err := r.readBody(req)
	if err != nil {
		r.errors.Add(1)
		http.Error(w, "failed to read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.bytesReceived.Add(uint64(len(body)))

	// Parse based on content type
	contentType := req.Header.Get("Content-Type")

	msg := &HTTPMessage{
		TenantID:    tenantID,
		SourceType:  sourceType,
		Timestamp:   time.Now(),
		ContentType: contentType,
		Headers:     extractHeaders(req),
		RemoteAddr:  req.RemoteAddr,
		ReceivedAt:  time.Now(),
	}

	// Try to parse as JSON array
	if strings.Contains(contentType, "application/json") {
		var logs []json.RawMessage

		// Try array first
		if err := json.Unmarshal(body, &logs); err != nil {
			// Try single object
			var single json.RawMessage
			if err := json.Unmarshal(body, &single); err == nil {
				logs = []json.RawMessage{single}
			} else {
				// Store as raw
				msg.RawBody = body
			}
		}
		msg.Logs = logs
	} else if strings.Contains(contentType, "text/plain") || strings.Contains(contentType, "application/x-ndjson") {
		// Parse newline-delimited JSON or plain text
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				msg.Logs = append(msg.Logs, json.RawMessage(line))
			}
		}
	} else {
		msg.RawBody = body
	}

	// Send to output channel
	select {
	case r.output <- msg:
		r.messagesReceived.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		count := len(msg.Logs)
		if count == 0 && len(msg.RawBody) > 0 {
			count = 1
		}
		fmt.Fprintf(w, `{"status":"accepted","count":%d}`, count)
	default:
		r.errors.Add(1)
		http.Error(w, "service overloaded", http.StatusServiceUnavailable)
	}
}

func (r *HTTPReceiver) readBody(req *http.Request) ([]byte, error) {
	var reader io.Reader = req.Body

	// Handle gzip compression
	if req.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(req.Body)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Limit body size
	reader = io.LimitReader(reader, r.config.MaxBodySize)

	return io.ReadAll(reader)
}

func extractHeaders(req *http.Request) map[string]string {
	headers := make(map[string]string)
	for key, values := range req.Header {
		if len(values) > 0 {
			// Skip sensitive headers
			lowerKey := strings.ToLower(key)
			if lowerKey != "authorization" && lowerKey != "x-api-key" {
				headers[key] = values[0]
			}
		}
	}
	return headers
}

// Simple token bucket rate limiter
type rateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate int
	lastRefill time.Time
	mu         sync.Mutex
}

func newRateLimiter(rps, burst int) *rateLimiter {
	return &rateLimiter{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: rps,
		lastRefill: time.Now(),
	}
}

func (rl *rateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	refill := int(elapsed.Seconds() * float64(rl.refillRate))
	if refill > 0 {
		rl.tokens += refill
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

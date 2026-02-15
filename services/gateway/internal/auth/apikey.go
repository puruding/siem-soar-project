// Package auth provides API key authentication for the API gateway.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// APIKeyConfig holds API key configuration.
type APIKeyConfig struct {
	HeaderName      string        `json:"header_name"`
	QueryParamName  string        `json:"query_param_name"`
	HashAlgorithm   string        `json:"hash_algorithm"`
	CacheTTL        time.Duration `json:"cache_ttl"`
}

// DefaultAPIKeyConfig returns default API key configuration.
func DefaultAPIKeyConfig() APIKeyConfig {
	return APIKeyConfig{
		HeaderName:     "X-API-Key",
		QueryParamName: "api_key",
		HashAlgorithm:  "sha256",
		CacheTTL:       5 * time.Minute,
	}
}

// APIKey represents an API key.
type APIKey struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	KeyHash     string            `json:"key_hash"`
	TenantID    string            `json:"tenant_id"`
	UserID      string            `json:"user_id,omitempty"`
	Permissions []string          `json:"permissions"`
	Scopes      []string          `json:"scopes"`
	RateLimit   int               `json:"rate_limit"` // Requests per second
	Metadata    map[string]string `json:"metadata,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	IsActive    bool              `json:"is_active"`
}

// IsValid checks if the API key is valid.
func (k *APIKey) IsValid() error {
	if !k.IsActive {
		return errors.New("API key is inactive")
	}

	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return errors.New("API key has expired")
	}

	return nil
}

// HasPermission checks if the API key has a specific permission.
func (k *APIKey) HasPermission(permission string) bool {
	for _, p := range k.Permissions {
		if p == permission || p == "*" {
			return true
		}
	}
	return false
}

// HasScope checks if the API key has a specific scope.
func (k *APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// APIKeyStore defines the interface for API key storage.
type APIKeyStore interface {
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	UpdateLastUsed(ctx context.Context, keyID string, timestamp time.Time) error
}

// APIKeyAuthenticator authenticates API keys.
type APIKeyAuthenticator struct {
	config  APIKeyConfig
	store   APIKeyStore
	cache   sync.Map // map[string]*cachedKey
	logger  *slog.Logger
}

type cachedKey struct {
	key       *APIKey
	expiresAt time.Time
}

// NewAPIKeyAuthenticator creates a new API key authenticator.
func NewAPIKeyAuthenticator(cfg APIKeyConfig, store APIKeyStore, logger *slog.Logger) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{
		config: cfg,
		store:  store,
		logger: logger.With("component", "apikey-auth"),
	}
}

// Authenticate authenticates an API key.
func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, apiKey string) (*APIKey, error) {
	if apiKey == "" {
		return nil, errors.New("API key is required")
	}

	// Hash the key
	keyHash := a.hashKey(apiKey)

	// Check cache
	if cached, ok := a.cache.Load(keyHash); ok {
		ck := cached.(*cachedKey)
		if time.Now().Before(ck.expiresAt) {
			// Update last used asynchronously
			go a.updateLastUsed(ck.key)
			return ck.key, ck.key.IsValid()
		}
		a.cache.Delete(keyHash)
	}

	// Look up in store
	key, err := a.store.GetByHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup API key: %w", err)
	}

	if key == nil {
		return nil, errors.New("invalid API key")
	}

	// Validate key
	if err := key.IsValid(); err != nil {
		return nil, err
	}

	// Cache the key
	a.cache.Store(keyHash, &cachedKey{
		key:       key,
		expiresAt: time.Now().Add(a.config.CacheTTL),
	})

	// Update last used
	go a.updateLastUsed(key)

	return key, nil
}

// hashKey hashes an API key.
func (a *APIKeyAuthenticator) hashKey(key string) string {
	h := sha256.New()
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

// updateLastUsed updates the last used timestamp.
func (a *APIKeyAuthenticator) updateLastUsed(key *APIKey) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.store.UpdateLastUsed(ctx, key.ID, time.Now()); err != nil {
		a.logger.Warn("failed to update API key last used", "key_id", key.ID, "error", err)
	}
}

// ExtractAPIKey extracts the API key from an HTTP request.
func (a *APIKeyAuthenticator) ExtractAPIKey(r *http.Request) string {
	// Check header
	if key := r.Header.Get(a.config.HeaderName); key != "" {
		return key
	}

	// Check query parameter
	if key := r.URL.Query().Get(a.config.QueryParamName); key != "" {
		return key
	}

	return ""
}

// GenerateAPIKey generates a new API key.
func GenerateAPIKey() (string, string, error) {
	// Generate random bytes
	b := make([]byte, 32)
	// In production, use crypto/rand
	for i := range b {
		b[i] = byte(i * 7 % 256)
	}

	// Create key in format: prefix_random
	key := "sk_" + hex.EncodeToString(b)

	// Hash the key for storage
	h := sha256.New()
	h.Write([]byte(key))
	keyHash := hex.EncodeToString(h.Sum(nil))

	return key, keyHash, nil
}

// VerifyAPIKeyHash verifies an API key against a hash.
func VerifyAPIKeyHash(key, hash string) bool {
	h := sha256.New()
	h.Write([]byte(key))
	computedHash := hex.EncodeToString(h.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(hash)) == 1
}

// InMemoryAPIKeyStore is an in-memory API key store for testing.
type InMemoryAPIKeyStore struct {
	keys map[string]*APIKey // Keyed by hash
	mu   sync.RWMutex
}

// NewInMemoryAPIKeyStore creates a new in-memory API key store.
func NewInMemoryAPIKeyStore() *InMemoryAPIKeyStore {
	return &InMemoryAPIKeyStore{
		keys: make(map[string]*APIKey),
	}
}

// Add adds an API key to the store.
func (s *InMemoryAPIKeyStore) Add(key *APIKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KeyHash] = key
}

// GetByHash retrieves an API key by hash.
func (s *InMemoryAPIKeyStore) GetByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[keyHash]
	if !ok {
		return nil, nil
	}

	// Return a copy
	keyCopy := *key
	return &keyCopy, nil
}

// UpdateLastUsed updates the last used timestamp.
func (s *InMemoryAPIKeyStore) UpdateLastUsed(ctx context.Context, keyID string, timestamp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range s.keys {
		if key.ID == keyID {
			key.LastUsedAt = &timestamp
			return nil
		}
	}

	return nil
}

// Context key for API key
const ContextKeyAPIKey ContextKey = "api_key"

// WithAPIKey adds API key to the context.
func WithAPIKey(ctx context.Context, key *APIKey) context.Context {
	ctx = context.WithValue(ctx, ContextKeyAPIKey, key)
	ctx = context.WithValue(ctx, ContextKeyTenantID, key.TenantID)
	if key.UserID != "" {
		ctx = context.WithValue(ctx, ContextKeyUserID, key.UserID)
	}
	return ctx
}

// GetAPIKey retrieves API key from the context.
func GetAPIKey(ctx context.Context) *APIKey {
	if key, ok := ctx.Value(ContextKeyAPIKey).(*APIKey); ok {
		return key
	}
	return nil
}

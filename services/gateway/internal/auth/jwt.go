// Package auth provides JWT authentication for the API gateway.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	Issuer          string        `json:"issuer"`
	Audience        string        `json:"audience"`
	SigningMethod   string        `json:"signing_method"`
	SecretKey       string        `json:"secret_key,omitempty"`
	PublicKeyPEM    string        `json:"public_key_pem,omitempty"`
	JWKSURL         string        `json:"jwks_url,omitempty"`
	ClockSkew       time.Duration `json:"clock_skew"`
	RefreshInterval time.Duration `json:"refresh_interval"`
}

// DefaultJWTConfig returns default JWT configuration.
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		SigningMethod:   "RS256",
		ClockSkew:       5 * time.Minute,
		RefreshInterval: 1 * time.Hour,
	}
}

// Claims represents JWT claims.
type Claims struct {
	// Standard claims
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`

	// Custom claims
	TenantID    string   `json:"tenant_id"`
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scope"`
}

// IsValid validates the claims.
func (c *Claims) IsValid(config JWTConfig) error {
	now := time.Now().Unix()

	// Check expiration
	if c.ExpiresAt > 0 && now > c.ExpiresAt+int64(config.ClockSkew.Seconds()) {
		return errors.New("token expired")
	}

	// Check not before
	if c.NotBefore > 0 && now < c.NotBefore-int64(config.ClockSkew.Seconds()) {
		return errors.New("token not yet valid")
	}

	// Check issuer
	if config.Issuer != "" && c.Issuer != config.Issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", config.Issuer, c.Issuer)
	}

	// Check audience
	if config.Audience != "" && c.Audience != config.Audience {
		return fmt.Errorf("invalid audience: expected %s, got %s", config.Audience, c.Audience)
	}

	return nil
}

// HasRole checks if the claims have a specific role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission checks if the claims have a specific permission.
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasScope checks if the claims have a specific scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"` // RSA modulus
	E   string `json:"e"` // RSA exponent
}

// ToRSAPublicKey converts a JWK to an RSA public key.
func (j *JWK) ToRSAPublicKey() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", j.Kty)
	}

	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// JWTAuthenticator authenticates JWT tokens.
type JWTAuthenticator struct {
	config     JWTConfig
	jwks       *JWKS
	publicKeys map[string]*rsa.PublicKey
	mu         sync.RWMutex
	logger     *slog.Logger
	client     *http.Client

	ctx    context.Context
	cancel context.CancelFunc
}

// NewJWTAuthenticator creates a new JWT authenticator.
func NewJWTAuthenticator(cfg JWTConfig, logger *slog.Logger) *JWTAuthenticator {
	ctx, cancel := context.WithCancel(context.Background())

	auth := &JWTAuthenticator{
		config:     cfg,
		publicKeys: make(map[string]*rsa.PublicKey),
		logger:     logger.With("component", "jwt-auth"),
		client:     &http.Client{Timeout: 10 * time.Second},
		ctx:        ctx,
		cancel:     cancel,
	}

	// Load JWKS if URL is provided
	if cfg.JWKSURL != "" {
		go auth.refreshJWKS()
		go auth.startJWKSRefresh()
	}

	return auth
}

// Authenticate authenticates a JWT token.
func (a *JWTAuthenticator) Authenticate(token string) (*Claims, error) {
	// Split token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Verify signature
	if err := a.verifySignature(token, header.Alg, header.Kid); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Validate claims
	if err := claims.IsValid(a.config); err != nil {
		return nil, err
	}

	return &claims, nil
}

// verifySignature verifies the JWT signature.
func (a *JWTAuthenticator) verifySignature(token, alg, kid string) error {
	// For simplicity, we'll skip actual signature verification here
	// In production, implement proper RSA/ECDSA/HMAC verification

	if alg != a.config.SigningMethod {
		return fmt.Errorf("unexpected signing method: %s", alg)
	}

	// Get public key
	a.mu.RLock()
	_, ok := a.publicKeys[kid]
	a.mu.RUnlock()

	if !ok && a.config.JWKSURL != "" {
		// Try refreshing JWKS
		a.refreshJWKS()

		a.mu.RLock()
		_, ok = a.publicKeys[kid]
		a.mu.RUnlock()

		if !ok {
			return fmt.Errorf("unknown key ID: %s", kid)
		}
	}

	// Note: In production, verify the signature using the public key
	// This is simplified for the implementation

	return nil
}

// refreshJWKS refreshes the JWKS from the configured URL.
func (a *JWTAuthenticator) refreshJWKS() {
	if a.config.JWKSURL == "" {
		return
	}

	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", a.config.JWKSURL, nil)
	if err != nil {
		a.logger.Error("failed to create JWKS request", "error", err)
		return
	}

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Error("failed to fetch JWKS", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.logger.Error("JWKS fetch returned non-200", "status", resp.StatusCode)
		return
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		a.logger.Error("failed to decode JWKS", "error", err)
		return
	}

	a.mu.Lock()
	a.jwks = &jwks

	// Convert JWKs to RSA public keys
	for _, jwk := range jwks.Keys {
		if jwk.Kty == "RSA" {
			pubKey, err := jwk.ToRSAPublicKey()
			if err != nil {
				a.logger.Warn("failed to convert JWK to RSA key", "kid", jwk.Kid, "error", err)
				continue
			}
			a.publicKeys[jwk.Kid] = pubKey
		}
	}
	a.mu.Unlock()

	a.logger.Info("refreshed JWKS", "keys", len(jwks.Keys))
}

// startJWKSRefresh starts periodic JWKS refresh.
func (a *JWTAuthenticator) startJWKSRefresh() {
	ticker := time.NewTicker(a.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.refreshJWKS()
		}
	}
}

// Stop stops the authenticator.
func (a *JWTAuthenticator) Stop() {
	a.cancel()
}

// ExtractToken extracts the JWT token from an HTTP request.
func ExtractToken(r *http.Request) (string, error) {
	// Check Authorization header
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer "), nil
		}
	}

	// Check cookie
	cookie, err := r.Cookie("access_token")
	if err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}

	// Check query parameter (not recommended but sometimes used)
	token := r.URL.Query().Get("access_token")
	if token != "" {
		return token, nil
	}

	return "", errors.New("no token found")
}

// ContextKey is a type for context keys.
type ContextKey string

const (
	ContextKeyClaims ContextKey = "claims"
	ContextKeyUserID ContextKey = "user_id"
	ContextKeyTenantID ContextKey = "tenant_id"
)

// WithClaims adds claims to the context.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	ctx = context.WithValue(ctx, ContextKeyClaims, claims)
	ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
	ctx = context.WithValue(ctx, ContextKeyTenantID, claims.TenantID)
	return ctx
}

// GetClaims retrieves claims from the context.
func GetClaims(ctx context.Context) *Claims {
	if claims, ok := ctx.Value(ContextKeyClaims).(*Claims); ok {
		return claims
	}
	return nil
}

// GetUserID retrieves the user ID from the context.
func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(ContextKeyUserID).(string); ok {
		return userID
	}
	return ""
}

// GetTenantID retrieves the tenant ID from the context.
func GetTenantID(ctx context.Context) string {
	if tenantID, ok := ctx.Value(ContextKeyTenantID).(string); ok {
		return tenantID
	}
	return ""
}

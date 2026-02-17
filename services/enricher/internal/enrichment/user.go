// Package enrichment provides data enrichment capabilities.
package enrichment

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// UserInfo represents user information from directory services.
type UserInfo struct {
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"display_name"`
	FirstName     string    `json:"first_name"`
	LastName      string    `json:"last_name"`
	Department    string    `json:"department"`
	Title         string    `json:"title"`
	Manager       string    `json:"manager"`
	ManagerEmail  string    `json:"manager_email"`
	Groups        []string  `json:"groups"`
	Location      string    `json:"location"`
	Office        string    `json:"office"`
	Phone         string    `json:"phone"`
	EmployeeType  string    `json:"employee_type"` // employee, contractor, vendor, etc.
	AccountStatus string    `json:"account_status"` // active, disabled, locked
	LastLogin     time.Time `json:"last_login"`
	Created       time.Time `json:"created"`
	Modified      time.Time `json:"modified"`
	DN            string    `json:"dn,omitempty"`
}

// UserEnricherConfig holds user enricher configuration.
type UserEnricherConfig struct {
	LDAPEndpoint     string
	LDAPBaseDN       string
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPUseTLS       bool
	CacheSize        int
	CacheTTL         time.Duration
	RequestTimeout   time.Duration
}

// UserEnricher provides user lookup functionality.
type UserEnricher struct {
	config     UserEnricherConfig
	ldapPool   chan *ldap.Conn
	cache      *userCache
	logger     *slog.Logger

	// In-memory fallback (for development/testing)
	localUsers map[string]*UserInfo
	localMu    sync.RWMutex

	// Metrics
	lookups     atomic.Uint64
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
	ldapLookups atomic.Uint64
	errors      atomic.Uint64
}

// NewUserEnricher creates a new user enricher.
func NewUserEnricher(cfg UserEnricherConfig, logger *slog.Logger) *UserEnricher {
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Second
	}

	enricher := &UserEnricher{
		config:     cfg,
		cache:      newUserCache(cfg.CacheSize, cfg.CacheTTL),
		logger:     logger.With("component", "user-enricher"),
		localUsers: make(map[string]*UserInfo),
	}

	// Initialize LDAP connection pool if configured
	if cfg.LDAPEndpoint != "" {
		enricher.ldapPool = make(chan *ldap.Conn, 10)
		// Pre-populate pool with connections
		for i := 0; i < 5; i++ {
			conn, err := enricher.createLDAPConnection()
			if err != nil {
				logger.Warn("failed to create LDAP connection", "error", err)
				continue
			}
			enricher.ldapPool <- conn
		}
	}

	return enricher
}

// Close closes the user enricher and its connections.
func (e *UserEnricher) Close() error {
	if e.ldapPool != nil {
		close(e.ldapPool)
		for conn := range e.ldapPool {
			conn.Close()
		}
	}
	return nil
}

// LookupByUsername looks up user by username.
func (e *UserEnricher) LookupByUsername(ctx context.Context, username string) (*UserInfo, error) {
	return e.lookup(ctx, "username", username)
}

// LookupByEmail looks up user by email address.
func (e *UserEnricher) LookupByEmail(ctx context.Context, email string) (*UserInfo, error) {
	return e.lookup(ctx, "email", email)
}

// LookupByUserID looks up user by user ID.
func (e *UserEnricher) LookupByUserID(ctx context.Context, userID string) (*UserInfo, error) {
	return e.lookup(ctx, "userid", userID)
}

func (e *UserEnricher) lookup(ctx context.Context, field, value string) (*UserInfo, error) {
	e.lookups.Add(1)
	cacheKey := fmt.Sprintf("%s:%s", field, value)

	// Check cache
	if user := e.cache.get(cacheKey); user != nil {
		e.cacheHits.Add(1)
		return user, nil
	}
	e.cacheMisses.Add(1)

	// Check local users (for development)
	e.localMu.RLock()
	if user := e.findLocalUser(field, value); user != nil {
		e.localMu.RUnlock()
		e.cache.set(cacheKey, user)
		return user, nil
	}
	e.localMu.RUnlock()

	// Query LDAP
	if e.config.LDAPEndpoint == "" {
		return nil, fmt.Errorf("user not found and LDAP not configured")
	}

	user, err := e.queryLDAP(ctx, field, value)
	if err != nil {
		e.errors.Add(1)
		return nil, err
	}

	// Cache result
	e.cache.set(cacheKey, user)

	return user, nil
}

func (e *UserEnricher) findLocalUser(field, value string) *UserInfo {
	for _, user := range e.localUsers {
		switch field {
		case "username":
			if user.Username == value {
				return user
			}
		case "email":
			if user.Email == value {
				return user
			}
		case "userid":
			if user.UserID == value {
				return user
			}
		}
	}
	return nil
}

func (e *UserEnricher) createLDAPConnection() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if e.config.LDAPUseTLS {
		conn, err = ldap.DialTLS("tcp", e.config.LDAPEndpoint, &tls.Config{
			InsecureSkipVerify: false,
		})
	} else {
		conn, err = ldap.Dial("tcp", e.config.LDAPEndpoint)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	// Bind with service account
	if e.config.LDAPBindDN != "" {
		if err := conn.Bind(e.config.LDAPBindDN, e.config.LDAPBindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
		}
	}

	return conn, nil
}

func (e *UserEnricher) getConnection() (*ldap.Conn, error) {
	select {
	case conn := <-e.ldapPool:
		return conn, nil
	default:
		// Pool exhausted, create new connection
		return e.createLDAPConnection()
	}
}

func (e *UserEnricher) returnConnection(conn *ldap.Conn) {
	select {
	case e.ldapPool <- conn:
		// Connection returned to pool
	default:
		// Pool full, close connection
		conn.Close()
	}
}

func (e *UserEnricher) queryLDAP(ctx context.Context, field, value string) (*UserInfo, error) {
	e.ldapLookups.Add(1)

	conn, err := e.getConnection()
	if err != nil {
		return nil, err
	}
	defer e.returnConnection(conn)

	// Build search filter based on field
	var filter string
	switch field {
	case "username":
		filter = fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(value))
	case "email":
		filter = fmt.Sprintf("(mail=%s)", ldap.EscapeFilter(value))
	case "userid":
		filter = fmt.Sprintf("(employeeID=%s)", ldap.EscapeFilter(value))
	default:
		filter = fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(value))
	}

	// Search attributes
	attributes := []string{
		"sAMAccountName",
		"mail",
		"displayName",
		"givenName",
		"sn",
		"department",
		"title",
		"manager",
		"memberOf",
		"physicalDeliveryOfficeName",
		"l",
		"telephoneNumber",
		"employeeType",
		"employeeID",
		"userAccountControl",
		"lastLogon",
		"whenCreated",
		"whenChanged",
		"distinguishedName",
	}

	searchRequest := ldap.NewSearchRequest(
		e.config.LDAPBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,  // size limit
		int(e.config.RequestTimeout.Seconds()),
		false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	entry := result.Entries[0]
	user := &UserInfo{
		UserID:      entry.GetAttributeValue("employeeID"),
		Username:    entry.GetAttributeValue("sAMAccountName"),
		Email:       entry.GetAttributeValue("mail"),
		DisplayName: entry.GetAttributeValue("displayName"),
		FirstName:   entry.GetAttributeValue("givenName"),
		LastName:    entry.GetAttributeValue("sn"),
		Department:  entry.GetAttributeValue("department"),
		Title:       entry.GetAttributeValue("title"),
		Manager:     e.extractCN(entry.GetAttributeValue("manager")),
		Groups:      e.extractGroups(entry.GetAttributeValues("memberOf")),
		Location:    entry.GetAttributeValue("l"),
		Office:      entry.GetAttributeValue("physicalDeliveryOfficeName"),
		Phone:       entry.GetAttributeValue("telephoneNumber"),
		EmployeeType: entry.GetAttributeValue("employeeType"),
		DN:          entry.GetAttributeValue("distinguishedName"),
	}

	// Parse account status from userAccountControl
	if uac := entry.GetAttributeValue("userAccountControl"); uac != "" {
		user.AccountStatus = e.parseAccountStatus(uac)
	}

	// Parse timestamps
	if ts := entry.GetAttributeValue("lastLogon"); ts != "" {
		user.LastLogin = e.parseWindowsTimestamp(ts)
	}
	if ts := entry.GetAttributeValue("whenCreated"); ts != "" {
		user.Created = e.parseLDAPTimestamp(ts)
	}
	if ts := entry.GetAttributeValue("whenChanged"); ts != "" {
		user.Modified = e.parseLDAPTimestamp(ts)
	}

	return user, nil
}

func (e *UserEnricher) extractCN(dn string) string {
	// Extract CN from DN like "CN=John Smith,OU=Users,DC=corp,DC=com"
	if len(dn) < 3 {
		return dn
	}
	if dn[:3] == "CN=" {
		for i := 3; i < len(dn); i++ {
			if dn[i] == ',' {
				return dn[3:i]
			}
		}
		return dn[3:]
	}
	return dn
}

func (e *UserEnricher) extractGroups(memberOf []string) []string {
	groups := make([]string, 0, len(memberOf))
	for _, dn := range memberOf {
		groups = append(groups, e.extractCN(dn))
	}
	return groups
}

func (e *UserEnricher) parseAccountStatus(uac string) string {
	// Parse userAccountControl flags
	// 0x0002 = ACCOUNTDISABLE
	// 0x0010 = LOCKOUT
	var flags int
	fmt.Sscanf(uac, "%d", &flags)

	if flags&0x0002 != 0 {
		return "disabled"
	}
	if flags&0x0010 != 0 {
		return "locked"
	}
	return "active"
}

func (e *UserEnricher) parseWindowsTimestamp(ts string) time.Time {
	// Windows FILETIME is 100-nanosecond intervals since January 1, 1601
	var ft int64
	fmt.Sscanf(ts, "%d", &ft)
	if ft == 0 {
		return time.Time{}
	}
	// Convert to Unix timestamp
	unixNano := (ft - 116444736000000000) * 100
	return time.Unix(0, unixNano)
}

func (e *UserEnricher) parseLDAPTimestamp(ts string) time.Time {
	// LDAP GeneralizedTime format: 20060102150405.0Z
	layouts := []string{
		"20060102150405.0Z",
		"20060102150405Z",
		"20060102150405",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, ts); err == nil {
			return t
		}
	}
	return time.Time{}
}

// RegisterLocalUser registers a user in local cache (for development/testing).
func (e *UserEnricher) RegisterLocalUser(user *UserInfo) {
	e.localMu.Lock()
	defer e.localMu.Unlock()
	key := user.Username
	if key == "" {
		key = user.UserID
	}
	e.localUsers[key] = user
}

// Stats returns enricher statistics.
func (e *UserEnricher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"lookups":      e.lookups.Load(),
		"cache_hits":   e.cacheHits.Load(),
		"cache_misses": e.cacheMisses.Load(),
		"ldap_lookups": e.ldapLookups.Load(),
		"errors":       e.errors.Load(),
		"cache_size":   e.cache.size(),
	}
}

// userCache is a TTL cache for user info.
type userCache struct {
	items   map[string]*userCacheItem
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

type userCacheItem struct {
	user      *UserInfo
	expiresAt time.Time
}

func newUserCache(maxSize int, ttl time.Duration) *userCache {
	if maxSize <= 0 {
		maxSize = 50000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	c := &userCache{
		items:   make(map[string]*userCacheItem),
		maxSize: maxSize,
		ttl:     ttl,
	}

	go c.cleanup()

	return c
}

func (c *userCache) get(key string) *UserInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		return nil
	}
	return item.user
}

func (c *userCache) set(key string, user *UserInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[key] = &userCacheItem{
		user:      user,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *userCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *userCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, item := range c.items {
		if oldestKey == "" || item.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.expiresAt
		}
	}

	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}

func (c *userCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.items {
			if now.After(item.expiresAt) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

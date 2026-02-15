// Package korea provides Korean Threat Intelligence integrations.
// Manager handles orchestration of Korean TI sources.
package korea

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ManagerConfig holds Korea TI Manager configuration.
type ManagerConfig struct {
	KISAConfig  *KISAConfig  `json:"kisa"`
	FSSConfig   *FSSConfig   `json:"fss"`
	SyncInterval time.Duration `json:"sync_interval"`
	BatchSize    int           `json:"batch_size"`
	EnableKISA   bool          `json:"enable_kisa"`
	EnableFSS    bool          `json:"enable_fss"`
}

// DefaultManagerConfig returns default manager configuration.
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		KISAConfig:   DefaultKISAConfig(),
		FSSConfig:    DefaultFSSConfig(),
		SyncInterval: 1 * time.Hour,
		BatchSize:    1000,
		EnableKISA:   true,
		EnableFSS:    true,
	}
}

// Manager manages Korean TI sources.
type Manager struct {
	config     *ManagerConfig
	kisaClient *KISAClient
	fssClient  *FSSClient
	logger     *slog.Logger
	iocHandler IOCHandler

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// Metrics
	lastKISASync   atomic.Value
	lastFSSSync    atomic.Value
	kisaIOCCount   atomic.Int64
	fssIOCCount    atomic.Int64
	syncErrors     atomic.Int64
}

// IOCHandler handles IOCs fetched from Korean TI sources.
type IOCHandler interface {
	HandleIOCs(ctx context.Context, iocs []*IOC) error
}

// NewManager creates a new Korean TI Manager.
func NewManager(config *ManagerConfig, handler IOCHandler, logger *slog.Logger) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:     config,
		iocHandler: handler,
		logger:     logger.With("component", "korea-ti-manager"),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Initialize clients
	if config.EnableKISA && config.KISAConfig != nil {
		m.kisaClient = NewKISAClient(config.KISAConfig, logger)
	}

	if config.EnableFSS && config.FSSConfig != nil {
		m.fssClient = NewFSSClient(config.FSSConfig, logger)
	}

	return m
}

// Start starts the Korean TI Manager.
func (m *Manager) Start() error {
	m.logger.Info("starting Korean TI Manager")

	// Test connections
	if err := m.testConnections(m.ctx); err != nil {
		m.logger.Warn("connection test failed", "error", err)
	}

	// Start initial sync
	m.wg.Add(1)
	go m.syncLoop()

	m.logger.Info("Korean TI Manager started",
		"enable_kisa", m.config.EnableKISA,
		"enable_fss", m.config.EnableFSS,
		"sync_interval", m.config.SyncInterval)

	return nil
}

// Stop stops the Korean TI Manager.
func (m *Manager) Stop() error {
	m.logger.Info("stopping Korean TI Manager")
	m.cancel()
	m.wg.Wait()
	m.logger.Info("Korean TI Manager stopped")
	return nil
}

// Sync performs a synchronization of all enabled Korean TI sources.
func (m *Manager) Sync(ctx context.Context) error {
	m.logger.Info("starting Korean TI sync")

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Sync KISA
	if m.kisaClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.syncKISA(ctx); err != nil {
				m.logger.Error("KISA sync failed", "error", err)
				errCh <- fmt.Errorf("KISA: %w", err)
			}
		}()
	}

	// Sync FSS
	if m.fssClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.syncFSS(ctx); err != nil {
				m.logger.Error("FSS sync failed", "error", err)
				errCh <- fmt.Errorf("FSS: %w", err)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Collect errors
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		m.syncErrors.Add(int64(len(errs)))
		return fmt.Errorf("sync errors: %v", errs)
	}

	m.logger.Info("Korean TI sync completed",
		"kisa_iocs", m.kisaIOCCount.Load(),
		"fss_iocs", m.fssIOCCount.Load())

	return nil
}

// syncKISA synchronizes IOCs from KISA C-TAS.
func (m *Manager) syncKISA(ctx context.Context) error {
	m.logger.Info("syncing KISA C-TAS")

	// Get last sync time
	var lastSync time.Time
	if v := m.lastKISASync.Load(); v != nil {
		lastSync = v.(time.Time)
	}

	var allIOCs []*IOC

	// Fetch malicious IPs
	ips, err := m.kisaClient.GetMaliciousIPs(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch KISA IPs", "error", err)
	} else {
		for _, ip := range ips {
			ioc := &IOC{
				ID:          fmt.Sprintf("kisa:ip:%s", ip.IP),
				Type:        "ip",
				Value:       ip.IP,
				Source:      "KISA",
				FeedID:      "kisa-ctas",
				ThreatType:  mapKISAThreatType(ip.ThreatType),
				Severity:    mapConfidenceToSeverity(ip.Confidence),
				Confidence:  ip.Confidence,
				FirstSeen:   ip.FirstSeen,
				LastSeen:    ip.LastSeen,
				Description: ip.Description,
				Labels:      ip.Tags,
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Fetch malicious domains
	domains, err := m.kisaClient.GetMaliciousDomains(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch KISA domains", "error", err)
	} else {
		for _, domain := range domains {
			ioc := &IOC{
				ID:          fmt.Sprintf("kisa:domain:%s", domain.Domain),
				Type:        "domain",
				Value:       domain.Domain,
				Source:      "KISA",
				FeedID:      "kisa-ctas",
				ThreatType:  mapKISAThreatType(domain.ThreatType),
				Severity:    mapConfidenceToSeverity(domain.Confidence),
				Confidence:  domain.Confidence,
				FirstSeen:   domain.FirstSeen,
				LastSeen:    domain.LastSeen,
				Description: domain.Description,
				Labels:      domain.Tags,
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Fetch malicious URLs
	urls, err := m.kisaClient.GetMaliciousURLs(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch KISA URLs", "error", err)
	} else {
		for _, u := range urls {
			ioc := &IOC{
				ID:          fmt.Sprintf("kisa:url:%s", u.URL),
				Type:        "url",
				Value:       u.URL,
				Source:      "KISA",
				FeedID:      "kisa-ctas",
				ThreatType:  mapKISAThreatType(u.ThreatType),
				Severity:    mapConfidenceToSeverity(u.Confidence),
				Confidence:  u.Confidence,
				FirstSeen:   u.FirstSeen,
				LastSeen:    u.LastSeen,
				Description: u.Description,
				Labels:      u.Tags,
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Fetch malware hashes
	hashes, err := m.kisaClient.GetMalwareHashes(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch KISA hashes", "error", err)
	} else {
		for _, hash := range hashes {
			// Prefer SHA256, fallback to SHA1, then MD5
			hashValue := hash.SHA256
			hashType := "sha256"
			if hashValue == "" {
				hashValue = hash.SHA1
				hashType = "sha1"
			}
			if hashValue == "" {
				hashValue = hash.MD5
				hashType = "md5"
			}

			ioc := &IOC{
				ID:          fmt.Sprintf("kisa:%s:%s", hashType, hashValue),
				Type:        hashType,
				Value:       hashValue,
				Source:      "KISA",
				FeedID:      "kisa-ctas",
				ThreatType:  mapKISAThreatType(hash.ThreatType),
				Severity:    mapConfidenceToSeverity(hash.Confidence),
				Confidence:  hash.Confidence,
				FirstSeen:   hash.FirstSeen,
				LastSeen:    hash.LastSeen,
				Description: hash.Description,
				Labels:      hash.Tags,
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Process IOCs
	if len(allIOCs) > 0 && m.iocHandler != nil {
		if err := m.iocHandler.HandleIOCs(ctx, allIOCs); err != nil {
			return fmt.Errorf("failed to handle IOCs: %w", err)
		}
	}

	m.kisaIOCCount.Store(int64(len(allIOCs)))
	m.lastKISASync.Store(time.Now())

	m.logger.Info("KISA sync completed", "iocs", len(allIOCs))
	return nil
}

// syncFSS synchronizes IOCs from FSS.
func (m *Manager) syncFSS(ctx context.Context) error {
	m.logger.Info("syncing FSS")

	// Get last sync time
	var lastSync time.Time
	if v := m.lastFSSSync.Load(); v != nil {
		lastSync = v.(time.Time)
	}

	var allIOCs []*IOC

	// Fetch phishing sites
	sites, err := m.fssClient.GetPhishingSites(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch FSS phishing sites", "error", err)
	} else {
		for _, site := range sites {
			ioc := ConvertPhishingSiteToIOC(site, "fss")
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Fetch fraud IPs
	ips, err := m.fssClient.GetFraudIPs(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch FSS fraud IPs", "error", err)
	} else {
		for _, ip := range ips {
			ioc := ConvertFraudIPToIOC(ip, "fss")
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Fetch financial malware
	malware, err := m.fssClient.GetFinancialMalware(ctx, lastSync, m.config.BatchSize)
	if err != nil {
		m.logger.Warn("failed to fetch FSS malware", "error", err)
	} else {
		for _, mal := range malware {
			// Prefer SHA256
			hashValue := mal.SHA256
			hashType := "sha256"
			if hashValue == "" {
				hashValue = mal.MD5
				hashType = "md5"
			}

			ioc := &IOC{
				ID:          fmt.Sprintf("fss:%s:%s", hashType, hashValue),
				Type:        hashType,
				Value:       hashValue,
				Source:      "FSS",
				FeedID:      "fss",
				ThreatType:  "malware",
				Severity:    "high",
				Confidence:  85,
				FirstSeen:   mal.FirstSeen,
				LastSeen:    mal.LastSeen,
				Description: fmt.Sprintf("%s (%s)", mal.MalwareFamily, mal.MalwareType),
				Labels:      mal.Capabilities,
				IsActive:    true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			allIOCs = append(allIOCs, ioc)
		}
	}

	// Process IOCs
	if len(allIOCs) > 0 && m.iocHandler != nil {
		if err := m.iocHandler.HandleIOCs(ctx, allIOCs); err != nil {
			return fmt.Errorf("failed to handle IOCs: %w", err)
		}
	}

	m.fssIOCCount.Store(int64(len(allIOCs)))
	m.lastFSSSync.Store(time.Now())

	m.logger.Info("FSS sync completed", "iocs", len(allIOCs))
	return nil
}

// syncLoop runs the periodic sync.
func (m *Manager) syncLoop() {
	defer m.wg.Done()

	// Initial sync
	if err := m.Sync(m.ctx); err != nil {
		m.logger.Error("initial sync failed", "error", err)
	}

	ticker := time.NewTicker(m.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.Sync(m.ctx); err != nil {
				m.logger.Error("sync failed", "error", err)
			}
		}
	}
}

// testConnections tests connections to all enabled TI sources.
func (m *Manager) testConnections(ctx context.Context) error {
	var errs []error

	if m.kisaClient != nil {
		if err := m.kisaClient.Test(ctx); err != nil {
			errs = append(errs, fmt.Errorf("KISA: %w", err))
		} else {
			m.logger.Info("KISA C-TAS connection successful")
		}
	}

	if m.fssClient != nil {
		if err := m.fssClient.Test(ctx); err != nil {
			errs = append(errs, fmt.Errorf("FSS: %w", err))
		} else {
			m.logger.Info("FSS connection successful")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("connection test errors: %v", errs)
	}

	return nil
}

// Stats returns manager statistics.
func (m *Manager) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"kisa_ioc_count":  m.kisaIOCCount.Load(),
		"fss_ioc_count":   m.fssIOCCount.Load(),
		"sync_errors":     m.syncErrors.Load(),
		"kisa_enabled":    m.config.EnableKISA,
		"fss_enabled":     m.config.EnableFSS,
	}

	if v := m.lastKISASync.Load(); v != nil {
		stats["last_kisa_sync"] = v.(time.Time)
	}

	if v := m.lastFSSSync.Load(); v != nil {
		stats["last_fss_sync"] = v.(time.Time)
	}

	return stats
}

// LookupIP looks up an IP in all enabled Korean TI sources.
func (m *Manager) LookupIP(ctx context.Context, ip string) ([]*IOC, error) {
	var results []*IOC
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	if m.kisaClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.kisaClient.LookupIP(ctx, ip)
			if err != nil {
				m.logger.Debug("KISA IP lookup failed", "ip", ip, "error", err)
				return
			}
			if result != nil {
				ioc := &IOC{
					ID:          fmt.Sprintf("kisa:ip:%s", result.IP),
					Type:        "ip",
					Value:       result.IP,
					Source:      "KISA",
					ThreatType:  mapKISAThreatType(result.ThreatType),
					Severity:    mapConfidenceToSeverity(result.Confidence),
					Confidence:  result.Confidence,
					FirstSeen:   result.FirstSeen,
					LastSeen:    result.LastSeen,
					Description: result.Description,
					Labels:      result.Tags,
					IsActive:    true,
				}
				mu.Lock()
				results = append(results, ioc)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	close(errCh)

	return results, nil
}

// LookupDomain looks up a domain in all enabled Korean TI sources.
func (m *Manager) LookupDomain(ctx context.Context, domain string) ([]*IOC, error) {
	var results []*IOC
	var mu sync.Mutex
	var wg sync.WaitGroup

	if m.kisaClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.kisaClient.LookupDomain(ctx, domain)
			if err != nil {
				m.logger.Debug("KISA domain lookup failed", "domain", domain, "error", err)
				return
			}
			if result != nil {
				ioc := &IOC{
					ID:          fmt.Sprintf("kisa:domain:%s", result.Domain),
					Type:        "domain",
					Value:       result.Domain,
					Source:      "KISA",
					ThreatType:  mapKISAThreatType(result.ThreatType),
					Severity:    mapConfidenceToSeverity(result.Confidence),
					Confidence:  result.Confidence,
					FirstSeen:   result.FirstSeen,
					LastSeen:    result.LastSeen,
					Description: result.Description,
					Labels:      result.Tags,
					IsActive:    true,
				}
				mu.Lock()
				results = append(results, ioc)
				mu.Unlock()
			}
		}()
	}

	if m.fssClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			site, err := m.fssClient.LookupPhishingSite(ctx, domain)
			if err != nil {
				m.logger.Debug("FSS phishing lookup failed", "domain", domain, "error", err)
				return
			}
			if site != nil {
				ioc := ConvertPhishingSiteToIOC(*site, "fss")
				mu.Lock()
				results = append(results, ioc)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// LookupHash looks up a hash in all enabled Korean TI sources.
func (m *Manager) LookupHash(ctx context.Context, hash string) ([]*IOC, error) {
	var results []*IOC
	var mu sync.Mutex
	var wg sync.WaitGroup

	if m.kisaClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := m.kisaClient.LookupHash(ctx, hash)
			if err != nil {
				m.logger.Debug("KISA hash lookup failed", "hash", hash, "error", err)
				return
			}
			if result != nil {
				hashType := "sha256"
				hashValue := result.SHA256
				if hashValue == "" {
					hashType = "sha1"
					hashValue = result.SHA1
				}
				if hashValue == "" {
					hashType = "md5"
					hashValue = result.MD5
				}

				ioc := &IOC{
					ID:          fmt.Sprintf("kisa:%s:%s", hashType, hashValue),
					Type:        hashType,
					Value:       hashValue,
					Source:      "KISA",
					ThreatType:  mapKISAThreatType(result.ThreatType),
					Severity:    mapConfidenceToSeverity(result.Confidence),
					Confidence:  result.Confidence,
					FirstSeen:   result.FirstSeen,
					LastSeen:    result.LastSeen,
					Description: result.Description,
					Labels:      result.Tags,
					IsActive:    true,
				}
				mu.Lock()
				results = append(results, ioc)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}

func mapConfidenceToSeverity(confidence int) string {
	switch {
	case confidence >= 90:
		return "critical"
	case confidence >= 70:
		return "high"
	case confidence >= 50:
		return "medium"
	default:
		return "low"
	}
}

package classifier

import (
	"context"
	"testing"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
)

func TestNewTIMatcher(t *testing.T) {
	matcher := NewTIMatcher(nil)
	if matcher == nil {
		t.Fatal("NewTIMatcher returned nil")
	}

	if matcher.ipStore == nil {
		t.Error("ipStore is nil")
	}
	if matcher.domainStore == nil {
		t.Error("domainStore is nil")
	}
	if matcher.hashStore == nil {
		t.Error("hashStore is nil")
	}
	if matcher.bloom == nil {
		t.Error("bloom filter is nil")
	}
}

func TestIPStore(t *testing.T) {
	store := NewIPStore()

	// Test exact IP match
	ioc := &IOCEntry{
		Type:       IOCTypeIP,
		Value:      "192.0.2.1",
		Source:     "test",
		ThreatType: ThreatMalware,
		Confidence: 0.9,
	}
	store.Add("192.0.2.1", ioc)

	result := store.Search("192.0.2.1")
	if result == nil {
		t.Error("Expected to find IP 192.0.2.1")
	}
	if result.Value != "192.0.2.1" {
		t.Errorf("Expected value 192.0.2.1, got %s", result.Value)
	}

	// Test IP not found
	result = store.Search("192.0.2.2")
	if result != nil {
		t.Error("Expected nil for non-existent IP")
	}

	// Test CIDR match
	cidrIOC := &IOCEntry{
		Type:       IOCTypeIP,
		Value:      "10.0.0.0/8",
		Source:     "test",
		ThreatType: ThreatC2,
		Confidence: 0.8,
	}
	store.Add("10.0.0.0/8", cidrIOC)

	result = store.Search("10.1.2.3")
	if result == nil {
		t.Error("Expected to find IP in CIDR range 10.0.0.0/8")
	}
	if result.ThreatType != ThreatC2 {
		t.Errorf("Expected ThreatC2, got %s", result.ThreatType)
	}

	// Test count
	if store.Count() != 2 {
		t.Errorf("Expected count 2, got %d", store.Count())
	}

	// Test clear
	store.Clear()
	if store.Count() != 0 {
		t.Errorf("Expected count 0 after clear, got %d", store.Count())
	}
}

func TestDomainStore(t *testing.T) {
	store := NewDomainStore()

	// Test exact domain match
	ioc := &IOCEntry{
		Type:       IOCTypeDomain,
		Value:      "evil.com",
		Source:     "threatfox",
		ThreatType: ThreatPhishing,
		Confidence: 0.95,
	}
	store.Add("evil.com", ioc)

	result := store.Search("evil.com")
	if result == nil {
		t.Error("Expected to find domain evil.com")
	}

	// Test subdomain match
	result = store.Search("subdomain.evil.com")
	if result == nil {
		t.Error("Expected to find subdomain.evil.com via parent match")
	}

	// Test deep subdomain
	result = store.Search("deep.subdomain.evil.com")
	if result == nil {
		t.Error("Expected to find deep.subdomain.evil.com via parent match")
	}

	// Test domain not found
	result = store.Search("good.com")
	if result != nil {
		t.Error("Expected nil for non-existent domain")
	}

	// Test case insensitivity
	result = store.Search("EVIL.COM")
	if result == nil {
		t.Error("Expected case insensitive match for EVIL.COM")
	}

	// Test count
	if store.Count() != 1 {
		t.Errorf("Expected count 1, got %d", store.Count())
	}
}

func TestHashStore(t *testing.T) {
	store := NewHashStore()

	// Test MD5
	md5IOC := &IOCEntry{
		Type:       IOCTypeMD5,
		Value:      "d41d8cd98f00b204e9800998ecf8427e",
		Source:     "misp",
		ThreatType: ThreatMalware,
		Confidence: 0.99,
	}
	store.Add("d41d8cd98f00b204e9800998ecf8427e", md5IOC)

	result := store.Search("d41d8cd98f00b204e9800998ecf8427e")
	if result == nil {
		t.Error("Expected to find MD5 hash")
	}

	// Test SHA1
	sha1IOC := &IOCEntry{
		Type:       IOCTypeSHA1,
		Value:      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		Source:     "test",
		ThreatType: ThreatRansomware,
		Confidence: 0.95,
	}
	store.Add("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1IOC)

	result = store.Search("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	if result == nil {
		t.Error("Expected to find SHA1 hash")
	}

	// Test SHA256
	sha256IOC := &IOCEntry{
		Type:       IOCTypeSHA256,
		Value:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Source:     "test",
		ThreatType: ThreatBotnet,
		Confidence: 0.90,
	}
	store.Add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256IOC)

	result = store.Search("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if result == nil {
		t.Error("Expected to find SHA256 hash")
	}

	// Test case insensitivity
	result = store.Search("D41D8CD98F00B204E9800998ECF8427E")
	if result == nil {
		t.Error("Expected case insensitive match for MD5")
	}

	// Test count
	if store.Count() != 3 {
		t.Errorf("Expected count 3, got %d", store.Count())
	}
}

func TestBloomFilter(t *testing.T) {
	bf := NewBloomFilter(10000, 7)

	// Add items
	bf.Add("test1")
	bf.Add("test2")
	bf.Add("test3")

	// Check contains
	if !bf.Contains("test1") {
		t.Error("Expected bloom filter to contain test1")
	}
	if !bf.Contains("test2") {
		t.Error("Expected bloom filter to contain test2")
	}

	// False positive rate should be low but not zero for non-existent items
	// This is a probabilistic test
	falsePositives := 0
	for i := 0; i < 1000; i++ {
		if bf.Contains("nonexistent" + string(rune(i))) {
			falsePositives++
		}
	}

	// With 10000 bits and 7 hash functions, FP rate should be very low for 3 items
	if falsePositives > 50 {
		t.Errorf("Too many false positives: %d", falsePositives)
	}
}

func TestExtractIndicators(t *testing.T) {
	matcher := NewTIMatcher(nil)

	tests := []struct {
		name     string
		rawLog   string
		expected map[IOCType][]string
	}{
		{
			name:   "Extract IPv4",
			rawLog: "Connection from 203.0.113.42 to 198.51.100.23",
			expected: map[IOCType][]string{
				IOCTypeIP: {"203.0.113.42", "198.51.100.23"},
			},
		},
		{
			name:   "Extract MD5 hash",
			rawLog: "File hash: d41d8cd98f00b204e9800998ecf8427e",
			expected: map[IOCType][]string{
				IOCTypeMD5: {"d41d8cd98f00b204e9800998ecf8427e"},
			},
		},
		{
			name:   "Extract domain",
			rawLog: "DNS query for malware.evil.com",
			expected: map[IOCType][]string{
				IOCTypeDomain: {"malware.evil.com"},
			},
		},
		{
			name:   "Extract URL with domain",
			rawLog: "Downloaded from https://bad.example.org/malware.exe",
			expected: map[IOCType][]string{
				IOCTypeURL:    {"https://bad.example.org/malware.exe"},
				IOCTypeDomain: {"bad.example.org"},
			},
		},
		{
			name:   "Skip private IPs",
			rawLog: "Connection from 192.168.1.1 to 10.0.0.1 and 203.0.113.50",
			expected: map[IOCType][]string{
				IOCTypeIP: {"203.0.113.50"},
			},
		},
		{
			name:   "Extract email",
			rawLog: "Phishing email from attacker@evil.com",
			expected: map[IOCType][]string{
				IOCTypeEmail:  {"attacker@evil.com"},
				IOCTypeDomain: {"evil.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &model.PipelineEvent{
				RawLog: tt.rawLog,
			}

			indicators := matcher.ExtractIndicators(event)

			// Group by type
			byType := make(map[IOCType][]string)
			for _, ind := range indicators {
				byType[ind.Type] = append(byType[ind.Type], ind.Value)
			}

			for expectedType, expectedValues := range tt.expected {
				found := byType[expectedType]
				for _, ev := range expectedValues {
					contains := false
					for _, fv := range found {
						if fv == ev {
							contains = true
							break
						}
					}
					if !contains {
						t.Errorf("Expected to find %s of type %s", ev, expectedType)
					}
				}
			}
		})
	}
}

func TestMatchEvent(t *testing.T) {
	ctx := context.Background()
	matcher := NewTIMatcher(nil)

	// Load test IOCs
	testIOCs := []IOCEntry{
		{
			Type:       IOCTypeIP,
			Value:      "203.0.113.100",
			Source:     "threatfox",
			ThreatType: ThreatC2,
			Confidence: 0.95,
			FirstSeen:  time.Now().Add(-24 * time.Hour),
			LastSeen:   time.Now(),
		},
		{
			Type:       IOCTypeDomain,
			Value:      "malware.test",
			Source:     "abuseipdb",
			ThreatType: ThreatMalware,
			Confidence: 0.90,
		},
		{
			Type:       IOCTypeMD5,
			Value:      "098f6bcd4621d373cade4e832627b4f6",
			Source:     "misp",
			ThreatType: ThreatRansomware,
			Confidence: 0.99,
		},
	}

	if err := matcher.LoadFromFeed(ctx, "test", testIOCs); err != nil {
		t.Fatalf("Failed to load IOCs: %v", err)
	}

	// Test matching event
	event := &model.PipelineEvent{
		ID:       "test-event-1",
		TenantID: "tenant-1",
		RawLog:   "Connection to 203.0.113.100 detected, file hash 098f6bcd4621d373cade4e832627b4f6",
		Source:   "firewall",
	}

	matches, err := matcher.MatchEvent(ctx, event)
	if err != nil {
		t.Fatalf("MatchEvent failed: %v", err)
	}

	if len(matches) < 2 {
		t.Errorf("Expected at least 2 matches, got %d", len(matches))
	}

	// Verify match details
	foundIP := false
	foundHash := false
	for _, match := range matches {
		if match.IOC.Type == IOCTypeIP && match.IOC.Value == "203.0.113.100" {
			foundIP = true
			if match.IOC.ThreatType != ThreatC2 {
				t.Errorf("Expected ThreatC2, got %s", match.IOC.ThreatType)
			}
		}
		if match.IOC.Type == IOCTypeMD5 {
			foundHash = true
		}
	}

	if !foundIP {
		t.Error("Expected to find IP match")
	}
	if !foundHash {
		t.Error("Expected to find hash match")
	}
}

func TestGetConfidenceBoost(t *testing.T) {
	matcher := NewTIMatcher(nil)

	tests := []struct {
		name     string
		matches  []IOCMatch
		minBoost float32
		maxBoost float32
	}{
		{
			name:     "No matches",
			matches:  []IOCMatch{},
			minBoost: 0,
			maxBoost: 0,
		},
		{
			name: "ThreatFox C2",
			matches: []IOCMatch{
				{
					IOC: &IOCEntry{
						Source:     "threatfox",
						ThreatType: ThreatC2,
						Confidence: 0.95,
					},
				},
			},
			minBoost: 0.15,
			maxBoost: 0.25,
		},
		{
			name: "AbuseIPDB 90%+",
			matches: []IOCMatch{
				{
					IOC: &IOCEntry{
						Source:     "abuseipdb",
						ThreatType: ThreatMalware,
						Confidence: 0.92,
					},
				},
			},
			minBoost: 0.10,
			maxBoost: 0.20,
		},
		{
			name: "MISP high confidence",
			matches: []IOCMatch{
				{
					IOC: &IOCEntry{
						Source:     "misp",
						ThreatType: ThreatMalware,
						Confidence: 0.85,
					},
				},
			},
			minBoost: 0.12,
			maxBoost: 0.20,
		},
		{
			name: "Multiple matches with boost",
			matches: []IOCMatch{
				{
					IOC: &IOCEntry{
						Source:     "threatfox",
						ThreatType: ThreatC2,
						Confidence: 0.95,
					},
				},
				{
					IOC: &IOCEntry{
						Source:     "misp",
						ThreatType: ThreatRansomware,
						Confidence: 0.90,
					},
				},
				{
					IOC: &IOCEntry{
						Source:     "abuseipdb",
						ThreatType: ThreatMalware,
						Confidence: 0.95,
					},
				},
			},
			minBoost: 0.35,
			maxBoost: 0.50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			boost := matcher.GetConfidenceBoost(tt.matches)
			if boost < tt.minBoost || boost > tt.maxBoost {
				t.Errorf("Expected boost between %.2f and %.2f, got %.2f",
					tt.minBoost, tt.maxBoost, boost)
			}
		})
	}
}

func TestMatchIP(t *testing.T) {
	ctx := context.Background()
	matcher := NewTIMatcher(nil)

	// Add test IP
	matcher.AddIOC(&IOCEntry{
		Type:       IOCTypeIP,
		Value:      "198.51.100.50",
		Source:     "test",
		ThreatType: ThreatMalware,
		Confidence: 0.9,
	})

	// Test match
	result := matcher.MatchIP(ctx, "198.51.100.50")
	if result == nil {
		t.Error("Expected to match IP 198.51.100.50")
	}

	// Test no match
	result = matcher.MatchIP(ctx, "198.51.100.51")
	if result != nil {
		t.Error("Expected no match for 198.51.100.51")
	}
}

func TestMatchDomain(t *testing.T) {
	ctx := context.Background()
	matcher := NewTIMatcher(nil)

	// Add test domain
	matcher.AddIOC(&IOCEntry{
		Type:       IOCTypeDomain,
		Value:      "malicious.example",
		Source:     "test",
		ThreatType: ThreatPhishing,
		Confidence: 0.85,
	})

	// Test exact match
	result := matcher.MatchDomain(ctx, "malicious.example")
	if result == nil {
		t.Error("Expected to match domain malicious.example")
	}

	// Test subdomain match
	result = matcher.MatchDomain(ctx, "sub.malicious.example")
	if result == nil {
		t.Error("Expected to match subdomain sub.malicious.example")
	}

	// Test no match
	result = matcher.MatchDomain(ctx, "safe.example")
	if result != nil {
		t.Error("Expected no match for safe.example")
	}
}

func TestMatchHash(t *testing.T) {
	ctx := context.Background()
	matcher := NewTIMatcher(nil)

	testHash := "a" + "b" + "c" + "d" + "e" + "f" + "0" + "1" + "2" + "3" + "4" + "5" + "6" + "7" + "8" + "9" + "a" + "b" + "c" + "d" + "e" + "f" + "0" + "1" + "2" + "3" + "4" + "5" + "6" + "7" + "8" + "9"

	// Add test hash
	matcher.AddIOC(&IOCEntry{
		Type:       IOCTypeMD5,
		Value:      testHash,
		Source:     "test",
		ThreatType: ThreatMalware,
		Confidence: 0.95,
	})

	// Test match
	result := matcher.MatchHash(ctx, testHash)
	if result == nil {
		t.Error("Expected to match MD5 hash")
	}

	// Test case insensitivity
	result = matcher.MatchHash(ctx, "ABCDEF0123456789ABCDEF0123456789")
	if result == nil {
		t.Error("Expected case insensitive match for MD5")
	}

	// Test no match
	result = matcher.MatchHash(ctx, "00000000000000000000000000000000")
	if result != nil {
		t.Error("Expected no match for non-existent hash")
	}
}

func TestStats(t *testing.T) {
	matcher := NewTIMatcher(nil)

	// Add some IOCs
	matcher.AddIOC(&IOCEntry{Type: IOCTypeIP, Value: "1.2.3.4"})
	matcher.AddIOC(&IOCEntry{Type: IOCTypeDomain, Value: "test.com"})
	matcher.AddIOC(&IOCEntry{Type: IOCTypeMD5, Value: "abcdef0123456789abcdef0123456789"})

	stats := matcher.Stats()

	if stats["ip_count"].(int) != 1 {
		t.Errorf("Expected ip_count 1, got %v", stats["ip_count"])
	}
	if stats["domain_count"].(int) != 1 {
		t.Errorf("Expected domain_count 1, got %v", stats["domain_count"])
	}
	if stats["hash_count"].(int) != 1 {
		t.Errorf("Expected hash_count 1, got %v", stats["hash_count"])
	}
}

func TestClear(t *testing.T) {
	matcher := NewTIMatcher(nil)

	// Add IOCs
	matcher.AddIOC(&IOCEntry{Type: IOCTypeIP, Value: "1.2.3.4"})
	matcher.AddIOC(&IOCEntry{Type: IOCTypeDomain, Value: "test.com"})

	// Clear
	matcher.Clear()

	stats := matcher.Stats()
	if stats["ip_count"].(int) != 0 {
		t.Error("Expected ip_count 0 after clear")
	}
	if stats["domain_count"].(int) != 0 {
		t.Error("Expected domain_count 0 after clear")
	}
}

func BenchmarkMatchEvent(b *testing.B) {
	ctx := context.Background()
	matcher := NewTIMatcher(nil)

	// Load 10000 test IOCs
	iocs := make([]IOCEntry, 10000)
	for i := 0; i < 10000; i++ {
		iocs[i] = IOCEntry{
			Type:       IOCTypeIP,
			Value:      "192.0.2." + string(rune(i%256)) + string(rune(i/256%256)) + "." + string(rune(i/65536)),
			Source:     "test",
			ThreatType: ThreatMalware,
			Confidence: 0.9,
		}
	}
	matcher.LoadFromFeed(ctx, "test", iocs)

	event := &model.PipelineEvent{
		RawLog: "Connection from 192.0.2.50 to 203.0.113.100 with file hash d41d8cd98f00b204e9800998ecf8427e",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.MatchEvent(ctx, event)
	}
}

func BenchmarkExtractIndicators(b *testing.B) {
	matcher := NewTIMatcher(nil)

	event := &model.PipelineEvent{
		RawLog: `Connection established from 192.168.1.100 to 203.0.113.50:443
DNS query for malware.evil.com resolved to 198.51.100.23
File downloaded: https://bad.example.org/malware.exe
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Email from attacker@phishing.com detected`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matcher.ExtractIndicators(event)
	}
}

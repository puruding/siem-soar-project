// Package mocks provides mock implementations for testing SIEM/SOAR services
package mocks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// MockAlert represents a mock alert
type MockAlert struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Severity    string                 `json:"severity"`
	Status      string                 `json:"status"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MockEvent represents a mock event
type MockEvent struct {
	EventID   string                 `json:"event_id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Source    map[string]interface{} `json:"source"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// MockRule represents a mock detection rule
type MockRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Query       string `json:"query"`
	Enabled     bool   `json:"enabled"`
}

// MockPlaybook represents a mock playbook
type MockPlaybook struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Steps       []MockStep  `json:"steps"`
}

// MockStep represents a mock playbook step
type MockStep struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Action string `json:"action"`
}

// MockDataStore provides in-memory storage for mock data
type MockDataStore struct {
	mu        sync.RWMutex
	alerts    map[string]MockAlert
	events    []MockEvent
	rules     map[string]MockRule
	playbooks map[string]MockPlaybook
}

// NewMockDataStore creates a new mock data store with sample data
func NewMockDataStore() *MockDataStore {
	store := &MockDataStore{
		alerts:    make(map[string]MockAlert),
		events:    []MockEvent{},
		rules:     make(map[string]MockRule),
		playbooks: make(map[string]MockPlaybook),
	}
	store.loadSampleData()
	return store
}

func (s *MockDataStore) loadSampleData() {
	// Sample alerts
	s.alerts["alert-001"] = MockAlert{
		ID:          "alert-001",
		Title:       "SSH Brute Force Detected",
		Severity:    "high",
		Status:      "new",
		Source:      "detection_engine",
		Timestamp:   time.Now().Add(-1 * time.Hour),
		Description: "Multiple failed SSH login attempts detected",
	}

	s.alerts["alert-002"] = MockAlert{
		ID:          "alert-002",
		Title:       "Malware Detected",
		Severity:    "critical",
		Status:      "investigating",
		Source:      "edr",
		Timestamp:   time.Now().Add(-30 * time.Minute),
		Description: "Ransomware signature detected on endpoint",
	}

	// Sample rules
	s.rules["rule-001"] = MockRule{
		ID:          "rule-001",
		Name:        "SSH Brute Force Detection",
		Description: "Detects multiple failed SSH login attempts",
		Severity:    "high",
		Query:       "event_type = 'auth_failure' AND service = 'sshd' | count() > 5 by src_ip window 5m",
		Enabled:     true,
	}

	// Sample playbooks
	s.playbooks["playbook-001"] = MockPlaybook{
		ID:          "playbook-001",
		Name:        "SSH Brute Force Response",
		Description: "Automated response to SSH brute force attacks",
		Enabled:     true,
		Steps: []MockStep{
			{ID: "step-1", Name: "Enrich IP", Type: "action", Action: "enrichment.ip_lookup"},
			{ID: "step-2", Name: "Block IP", Type: "action", Action: "firewall.block_ip"},
		},
	}
}

// MockGatewayServer creates a mock API gateway server
type MockGatewayServer struct {
	*httptest.Server
	store *MockDataStore
}

// NewMockGatewayServer creates a new mock gateway server
func NewMockGatewayServer() *MockGatewayServer {
	store := NewMockDataStore()

	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "gateway",
		})
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ready",
		})
	})

	// Alert endpoints
	mux.HandleFunc("/api/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			store.mu.RLock()
			alerts := make([]MockAlert, 0, len(store.alerts))
			for _, alert := range store.alerts {
				alerts = append(alerts, alert)
			}
			store.mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"alerts": alerts,
				"total":  len(alerts),
			})
		case http.MethodPost:
			var alert MockAlert
			if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			store.mu.Lock()
			alert.ID = fmt.Sprintf("alert-%d", time.Now().UnixNano())
			alert.Timestamp = time.Now()
			store.alerts[alert.ID] = alert
			store.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(alert)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Rules endpoints
	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			store.mu.RLock()
			rules := make([]MockRule, 0, len(store.rules))
			for _, rule := range store.rules {
				rules = append(rules, rule)
			}
			store.mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"rules": rules,
			})
		case http.MethodPost:
			var rule MockRule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			store.mu.Lock()
			rule.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
			store.rules[rule.ID] = rule
			store.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"message": "rule created"})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Playbook endpoints
	mux.HandleFunc("/api/v1/playbooks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			store.mu.RLock()
			playbooks := make([]MockPlaybook, 0, len(store.playbooks))
			for _, pb := range store.playbooks {
				playbooks = append(playbooks, pb)
			}
			store.mu.RUnlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"playbooks": playbooks,
			})
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"message": "playbook created"})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Query endpoint
	mux.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"results":  []interface{}{},
			"metadata": map[string]interface{}{"total": 0, "duration_ms": 10},
		})
	})

	server := httptest.NewServer(mux)

	return &MockGatewayServer{
		Server: server,
		store:  store,
	}
}

// MockCollectorServer creates a mock event collector server
type MockCollectorServer struct {
	*httptest.Server
	events []MockEvent
	mu     sync.RWMutex
}

// NewMockCollectorServer creates a new mock collector server
func NewMockCollectorServer() *MockCollectorServer {
	collector := &MockCollectorServer{
		events: []MockEvent{},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "collector",
		})
	})

	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Events []MockEvent `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		collector.mu.Lock()
		collector.events = append(collector.events, payload.Events...)
		collector.mu.Unlock()

		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": len(payload.Events),
		})
	})

	mux.HandleFunc("/api/v1/events/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Events []MockEvent `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		collector.mu.Lock()
		collector.events = append(collector.events, payload.Events...)
		collector.mu.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": len(payload.Events),
		})
	})

	collector.Server = httptest.NewServer(mux)
	return collector
}

// GetEvents returns collected events
func (c *MockCollectorServer) GetEvents() []MockEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]MockEvent{}, c.events...)
}

// MockClickHouseClient provides a mock ClickHouse client
type MockClickHouseClient struct {
	mu      sync.RWMutex
	queries []string
	results map[string]interface{}
}

// NewMockClickHouseClient creates a new mock ClickHouse client
func NewMockClickHouseClient() *MockClickHouseClient {
	return &MockClickHouseClient{
		queries: []string{},
		results: map[string]interface{}{
			"SELECT count() FROM events": []map[string]interface{}{{"count()": 1000}},
		},
	}
}

// Query executes a mock query
func (c *MockClickHouseClient) Query(ctx context.Context, query string) (interface{}, error) {
	c.mu.Lock()
	c.queries = append(c.queries, query)
	c.mu.Unlock()

	c.mu.RLock()
	result, ok := c.results[query]
	c.mu.RUnlock()

	if ok {
		return result, nil
	}
	return []map[string]interface{}{}, nil
}

// GetQueries returns executed queries
func (c *MockClickHouseClient) GetQueries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string{}, c.queries...)
}

// MockKafkaProducer provides a mock Kafka producer
type MockKafkaProducer struct {
	mu       sync.RWMutex
	messages []struct {
		Topic string
		Key   string
		Value []byte
	}
}

// NewMockKafkaProducer creates a new mock Kafka producer
func NewMockKafkaProducer() *MockKafkaProducer {
	return &MockKafkaProducer{}
}

// Produce sends a message to the mock producer
func (p *MockKafkaProducer) Produce(topic, key string, value []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.messages = append(p.messages, struct {
		Topic string
		Key   string
		Value []byte
	}{Topic: topic, Key: key, Value: value})
	return nil
}

// GetMessages returns produced messages
func (p *MockKafkaProducer) GetMessages() []struct {
	Topic string
	Key   string
	Value []byte
} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.messages
}

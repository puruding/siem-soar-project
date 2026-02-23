package pubsub

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Channel constants for pipeline pub/sub.
const (
	ChannelEvents          = "pipeline:events"
	ChannelClassifications = "pipeline:classifications"
	ChannelApprovals       = "pipeline:approvals"
	ChannelExecutions      = "pipeline:executions"
	ChannelAuditLogs       = "pipeline:audit_logs"
)

// PubSubConfig holds Redis pub/sub configuration.
type PubSubConfig struct {
	// RedisURL is the Redis connection URL (e.g., "redis://localhost:6379/0").
	RedisURL string

	// Addresses is a list of Redis addresses for cluster/sentinel mode.
	Addresses []string

	// Password for Redis authentication.
	Password string

	// DB is the Redis database number (default: 0).
	DB int

	// PoolSize is the maximum number of connections.
	PoolSize int

	// MinIdleConns is the minimum number of idle connections.
	MinIdleConns int

	// DialTimeout is the timeout for establishing a connection.
	DialTimeout time.Duration

	// ReadTimeout is the timeout for read operations.
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations.
	WriteTimeout time.Duration

	// MaxRetries is the maximum number of retries.
	MaxRetries int

	// RetryBackoff is the initial backoff duration for retries.
	RetryBackoff time.Duration
}

// DefaultConfig returns a default pub/sub configuration.
func DefaultConfig() PubSubConfig {
	return PubSubConfig{
		Addresses:    []string{"localhost:6379"},
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		MaxRetries:   3,
		RetryBackoff: 100 * time.Millisecond,
	}
}

// PubSub manages Redis pub/sub connections.
type PubSub struct {
	client       *redis.Client
	config       PubSubConfig
	subscribers  map[string]*redis.PubSub
	mu           sync.RWMutex
	logger       *slog.Logger
	reconnecting bool
	reconnectMu  sync.Mutex
}

// NewPubSub creates a new PubSub instance from a Redis URL.
func NewPubSub(redisURL string) (*PubSub, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis URL: %w", err)
	}

	client := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &PubSub{
		client:      client,
		config:      DefaultConfig(),
		subscribers: make(map[string]*redis.PubSub),
		logger:      slog.Default().With("component", "pubsub"),
	}, nil
}

// NewPubSubWithConfig creates a new PubSub instance with custom configuration.
func NewPubSubWithConfig(cfg PubSubConfig) (*PubSub, error) {
	var addr string
	if len(cfg.Addresses) > 0 {
		addr = cfg.Addresses[0]
	} else {
		addr = "localhost:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		MaxRetries:   cfg.MaxRetries,
	})

	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &PubSub{
		client:      client,
		config:      cfg,
		subscribers: make(map[string]*redis.PubSub),
		logger:      slog.Default().With("component", "pubsub"),
	}, nil
}

// Publish publishes a message to a channel.
func (p *PubSub) Publish(ctx context.Context, channel string, message interface{}) error {
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	if err := p.client.Publish(ctx, channel, data).Err(); err != nil {
		p.logger.Error("failed to publish message",
			"channel", channel,
			"error", err,
		)
		return fmt.Errorf("failed to publish to channel %s: %w", channel, err)
	}

	p.logger.Debug("message published",
		"channel", channel,
		"size", len(data),
	)

	return nil
}

// PublishString publishes a raw string message to a channel.
func (p *PubSub) PublishString(ctx context.Context, channel, message string) error {
	if err := p.client.Publish(ctx, channel, message).Err(); err != nil {
		return fmt.Errorf("failed to publish to channel %s: %w", channel, err)
	}
	return nil
}

// Subscribe subscribes to channels and returns a channel for messages.
func (p *PubSub) Subscribe(ctx context.Context, channels ...string) (<-chan *redis.Message, error) {
	if len(channels) == 0 {
		return nil, fmt.Errorf("at least one channel is required")
	}

	sub := p.client.Subscribe(ctx, channels...)

	// Wait for subscription confirmation
	_, err := sub.Receive(ctx)
	if err != nil {
		sub.Close()
		return nil, fmt.Errorf("failed to subscribe to channels: %w", err)
	}

	// Store subscriber for cleanup
	p.mu.Lock()
	key := generateSubscriberKey(channels)
	p.subscribers[key] = sub
	p.mu.Unlock()

	msgCh := sub.Channel()

	p.logger.Info("subscribed to channels",
		"channels", channels,
	)

	return msgCh, nil
}

// SubscribeWithHandler subscribes to channels and calls handler for each message.
func (p *PubSub) SubscribeWithHandler(ctx context.Context, handler func(*redis.Message), channels ...string) error {
	msgCh, err := p.Subscribe(ctx, channels...)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				p.logger.Info("subscription context cancelled",
					"channels", channels,
				)
				return
			case msg, ok := <-msgCh:
				if !ok {
					p.logger.Warn("subscription channel closed",
						"channels", channels,
					)
					// Attempt to reconnect
					p.handleReconnect(ctx, handler, channels)
					return
				}
				handler(msg)
			}
		}
	}()

	return nil
}

// PSubscribe subscribes to channels matching patterns.
func (p *PubSub) PSubscribe(ctx context.Context, patterns ...string) (<-chan *redis.Message, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("at least one pattern is required")
	}

	sub := p.client.PSubscribe(ctx, patterns...)

	_, err := sub.Receive(ctx)
	if err != nil {
		sub.Close()
		return nil, fmt.Errorf("failed to psubscribe to patterns: %w", err)
	}

	p.mu.Lock()
	key := "p:" + generateSubscriberKey(patterns)
	p.subscribers[key] = sub
	p.mu.Unlock()

	return sub.Channel(), nil
}

// Unsubscribe unsubscribes from channels.
func (p *PubSub) Unsubscribe(ctx context.Context, channels ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := generateSubscriberKey(channels)
	if sub, ok := p.subscribers[key]; ok {
		if err := sub.Unsubscribe(ctx, channels...); err != nil {
			return fmt.Errorf("failed to unsubscribe: %w", err)
		}
		if err := sub.Close(); err != nil {
			return fmt.Errorf("failed to close subscription: %w", err)
		}
		delete(p.subscribers, key)
	}

	return nil
}

// handleReconnect handles automatic reconnection after connection loss.
func (p *PubSub) handleReconnect(ctx context.Context, handler func(*redis.Message), channels []string) {
	p.reconnectMu.Lock()
	if p.reconnecting {
		p.reconnectMu.Unlock()
		return
	}
	p.reconnecting = true
	p.reconnectMu.Unlock()

	defer func() {
		p.reconnectMu.Lock()
		p.reconnecting = false
		p.reconnectMu.Unlock()
	}()

	backoff := p.config.RetryBackoff
	maxBackoff := 30 * time.Second

	for attempt := 1; attempt <= p.config.MaxRetries*3; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		p.logger.Info("attempting to reconnect",
			"attempt", attempt,
			"channels", channels,
		)

		// Test connection
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := p.client.Ping(pingCtx).Err(); err != nil {
			cancel()
			p.logger.Warn("reconnect ping failed",
				"attempt", attempt,
				"error", err,
			)
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		cancel()

		// Resubscribe
		if err := p.SubscribeWithHandler(ctx, handler, channels...); err != nil {
			p.logger.Warn("reconnect subscribe failed",
				"attempt", attempt,
				"error", err,
			)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		p.logger.Info("reconnected successfully",
			"channels", channels,
		)
		return
	}

	p.logger.Error("failed to reconnect after max retries",
		"channels", channels,
	)
}

// IsHealthy checks if the Redis connection is healthy.
func (p *PubSub) IsHealthy(ctx context.Context) bool {
	return p.client.Ping(ctx).Err() == nil
}

// Client returns the underlying Redis client.
func (p *PubSub) Client() *redis.Client {
	return p.client
}

// Close closes the Redis connection and all subscriptions.
func (p *PubSub) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	// Close all subscriptions
	for key, sub := range p.subscribers {
		if err := sub.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close subscription %s: %w", key, err))
		}
		delete(p.subscribers, key)
	}

	// Close the client
	if err := p.client.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close client: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}

	p.logger.Info("pubsub connection closed")
	return nil
}

// generateSubscriberKey generates a unique key for a set of channels.
func generateSubscriberKey(channels []string) string {
	if len(channels) == 1 {
		return channels[0]
	}
	key := ""
	for i, ch := range channels {
		if i > 0 {
			key += ","
		}
		key += ch
	}
	return key
}

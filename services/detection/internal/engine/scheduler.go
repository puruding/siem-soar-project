// Package engine provides the core detection engine implementation.
package engine

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/detection/internal/rule"
)

// ScheduledTask represents a scheduled detection task.
type ScheduledTask struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	RuleID        string        `json:"rule_id"`
	Schedule      string        `json:"schedule"` // Cron expression
	LastRun       time.Time     `json:"last_run"`
	NextRun       time.Time     `json:"next_run"`
	Enabled       bool          `json:"enabled"`
	Timeout       time.Duration `json:"timeout"`
	RetryCount    int           `json:"retry_count"`
	RetryDelay    time.Duration `json:"retry_delay"`
	TaskFunc      func(context.Context) error `json:"-"`
}

// SchedulerConfig holds scheduler configuration.
type SchedulerConfig struct {
	TickInterval    time.Duration `json:"tick_interval"`
	MaxConcurrent   int           `json:"max_concurrent"`
	DefaultTimeout  time.Duration `json:"default_timeout"`
}

// DefaultSchedulerConfig returns default scheduler configuration.
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		TickInterval:   time.Minute,
		MaxConcurrent:  10,
		DefaultTimeout: 5 * time.Minute,
	}
}

// Scheduler manages scheduled detection tasks.
type Scheduler struct {
	config     SchedulerConfig
	tasks      map[string]*ScheduledTask
	tasksMu    sync.RWMutex

	running    atomic.Bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	semaphore  chan struct{}
	logger     *slog.Logger

	// Metrics
	tasksExecuted atomic.Uint64
	tasksFailed   atomic.Uint64
	tasksSkipped  atomic.Uint64
}

// NewScheduler creates a new scheduler.
func NewScheduler(tickInterval time.Duration, logger *slog.Logger) *Scheduler {
	if tickInterval == 0 {
		tickInterval = time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Scheduler{
		config: SchedulerConfig{
			TickInterval:   tickInterval,
			MaxConcurrent:  10,
			DefaultTimeout: 5 * time.Minute,
		},
		tasks:     make(map[string]*ScheduledTask),
		ctx:       ctx,
		cancel:    cancel,
		semaphore: make(chan struct{}, 10),
		logger:    logger.With("component", "scheduler"),
	}
}

// Start starts the scheduler.
func (s *Scheduler) Start() {
	if s.running.Load() {
		return
	}

	s.running.Store(true)
	s.wg.Add(1)
	go s.run()

	s.logger.Info("scheduler started")
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() {
	if !s.running.Load() {
		return
	}

	s.running.Store(false)
	s.cancel()
	s.wg.Wait()

	s.logger.Info("scheduler stopped")
}

// AddTask adds a scheduled task.
func (s *Scheduler) AddTask(task *ScheduledTask) error {
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()

	if task.Timeout == 0 {
		task.Timeout = s.config.DefaultTimeout
	}

	// Calculate next run time based on schedule
	task.NextRun = s.calculateNextRun(task.Schedule, time.Now())

	s.tasks[task.ID] = task
	s.logger.Info("task added", "task_id", task.ID, "next_run", task.NextRun)

	return nil
}

// RemoveTask removes a scheduled task.
func (s *Scheduler) RemoveTask(taskID string) {
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()

	delete(s.tasks, taskID)
	s.logger.Info("task removed", "task_id", taskID)
}

// EnableTask enables a task.
func (s *Scheduler) EnableTask(taskID string) {
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()

	if task, ok := s.tasks[taskID]; ok {
		task.Enabled = true
		task.NextRun = s.calculateNextRun(task.Schedule, time.Now())
	}
}

// DisableTask disables a task.
func (s *Scheduler) DisableTask(taskID string) {
	s.tasksMu.Lock()
	defer s.tasksMu.Unlock()

	if task, ok := s.tasks[taskID]; ok {
		task.Enabled = false
	}
}

// GetTask returns a task by ID.
func (s *Scheduler) GetTask(taskID string) *ScheduledTask {
	s.tasksMu.RLock()
	defer s.tasksMu.RUnlock()

	return s.tasks[taskID]
}

// ListTasks returns all tasks.
func (s *Scheduler) ListTasks() []*ScheduledTask {
	s.tasksMu.RLock()
	defer s.tasksMu.RUnlock()

	tasks := make([]*ScheduledTask, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

// Stats returns scheduler statistics.
func (s *Scheduler) Stats() map[string]interface{} {
	return map[string]interface{}{
		"running":        s.running.Load(),
		"tasks_total":    len(s.tasks),
		"tasks_executed": s.tasksExecuted.Load(),
		"tasks_failed":   s.tasksFailed.Load(),
		"tasks_skipped":  s.tasksSkipped.Load(),
	}
}

func (s *Scheduler) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.TickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.tick(now)
		}
	}
}

func (s *Scheduler) tick(now time.Time) {
	s.tasksMu.RLock()
	defer s.tasksMu.RUnlock()

	for _, task := range s.tasks {
		if !task.Enabled {
			continue
		}

		if now.Before(task.NextRun) {
			continue
		}

		// Check semaphore (non-blocking)
		select {
		case s.semaphore <- struct{}{}:
			s.wg.Add(1)
			go s.executeTask(task)
		default:
			s.tasksSkipped.Add(1)
			s.logger.Warn("max concurrent tasks reached, skipping", "task_id", task.ID)
		}
	}
}

func (s *Scheduler) executeTask(task *ScheduledTask) {
	defer s.wg.Done()
	defer func() { <-s.semaphore }()

	ctx, cancel := context.WithTimeout(s.ctx, task.Timeout)
	defer cancel()

	logger := s.logger.With("task_id", task.ID, "rule_id", task.RuleID)
	logger.Info("executing task")

	start := time.Now()
	var err error

	for attempt := 0; attempt <= task.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(task.RetryDelay)
			logger.Info("retrying task", "attempt", attempt)
		}

		if task.TaskFunc != nil {
			err = task.TaskFunc(ctx)
			if err == nil {
				break
			}
		}
	}

	duration := time.Since(start)

	// Update task state
	s.tasksMu.Lock()
	if t, ok := s.tasks[task.ID]; ok {
		t.LastRun = time.Now()
		t.NextRun = s.calculateNextRun(t.Schedule, time.Now())
	}
	s.tasksMu.Unlock()

	if err != nil {
		s.tasksFailed.Add(1)
		logger.Error("task failed", "error", err, "duration", duration)
	} else {
		s.tasksExecuted.Add(1)
		logger.Info("task completed", "duration", duration)
	}
}

func (s *Scheduler) calculateNextRun(schedule string, from time.Time) time.Time {
	// Simplified cron parser - in production, use github.com/robfig/cron
	// Supports: @every <duration>, @hourly, @daily, @weekly
	switch schedule {
	case "@hourly":
		return from.Truncate(time.Hour).Add(time.Hour)
	case "@daily":
		return from.Truncate(24 * time.Hour).Add(24 * time.Hour)
	case "@weekly":
		daysUntilSunday := (7 - int(from.Weekday())) % 7
		if daysUntilSunday == 0 {
			daysUntilSunday = 7
		}
		return from.Truncate(24 * time.Hour).Add(time.Duration(daysUntilSunday) * 24 * time.Hour)
	default:
		// Try to parse @every <duration>
		if len(schedule) > 7 && schedule[:7] == "@every " {
			if d, err := time.ParseDuration(schedule[7:]); err == nil {
				return from.Add(d)
			}
		}
		// Default to 1 hour
		return from.Add(time.Hour)
	}
}

// ScheduleRule schedules a rule for periodic execution.
func (s *Scheduler) ScheduleRule(r *rule.Rule, executor *Executor, eventProvider EventProvider) error {
	if r.Schedule == "" {
		return nil // No schedule
	}

	task := &ScheduledTask{
		ID:         "rule:" + r.ID,
		Name:       r.Name,
		RuleID:     r.ID,
		Schedule:   r.Schedule,
		Enabled:    r.IsEnabled,
		Timeout:    5 * time.Minute,
		RetryCount: 2,
		RetryDelay: 30 * time.Second,
		TaskFunc: func(ctx context.Context) error {
			return s.executeScheduledRule(ctx, r, executor, eventProvider)
		},
	}

	return s.AddTask(task)
}

// EventProvider provides events for scheduled rules.
type EventProvider interface {
	GetEventsForRule(ctx context.Context, ruleID string, timeRange TimeRange) ([]*Event, error)
}

// TimeRange represents a time range for queries.
type TimeRange struct {
	Start time.Time
	End   time.Time
}

func (s *Scheduler) executeScheduledRule(ctx context.Context, r *rule.Rule, executor *Executor, provider EventProvider) error {
	// Get events for the rule's lookback period
	lookback := 15 * time.Minute // Default lookback
	if r.Lookback > 0 {
		lookback = r.Lookback
	}

	timeRange := TimeRange{
		Start: time.Now().Add(-lookback),
		End:   time.Now(),
	}

	events, err := provider.GetEventsForRule(ctx, r.ID, timeRange)
	if err != nil {
		return err
	}

	// Execute rule against events
	for _, event := range events {
		_, err := executor.Execute(ctx, r, event)
		if err != nil {
			s.logger.Error("scheduled rule execution failed", "rule_id", r.ID, "error", err)
		}
	}

	return nil
}

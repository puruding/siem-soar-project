// Package repository provides database access abstractions.
package repository

import (
	"context"
	"time"
)

// Pagination holds pagination parameters.
type Pagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

// DefaultPagination returns default pagination settings.
func DefaultPagination() Pagination {
	return Pagination{
		Page:     1,
		PageSize: 20,
	}
}

// Offset calculates the database offset for pagination.
func (p Pagination) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// Limit returns the page size as the limit.
func (p Pagination) Limit() int {
	return p.PageSize
}

// SortOrder represents sort direction.
type SortOrder string

const (
	SortAsc  SortOrder = "ASC"
	SortDesc SortOrder = "DESC"
)

// Sort holds sorting parameters.
type Sort struct {
	Field string    `json:"field"`
	Order SortOrder `json:"order"`
}

// Filter represents a query filter.
type Filter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, gte, lt, lte, like, in, between
	Value    interface{} `json:"value"`
}

// QueryOptions holds common query options.
type QueryOptions struct {
	Pagination Pagination
	Sorts      []Sort
	Filters    []Filter
}

// BaseEntity contains common fields for all entities.
type BaseEntity struct {
	ID        string    `json:"id" db:"id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Repository is a generic interface for CRUD operations.
type Repository[T any] interface {
	Create(ctx context.Context, entity *T) error
	GetByID(ctx context.Context, id string) (*T, error)
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, opts QueryOptions) ([]*T, int, error)
}

// Transaction represents a database transaction.
type Transaction interface {
	Commit() error
	Rollback() error
}

// TxFunc is a function that runs within a transaction.
type TxFunc func(ctx context.Context, tx Transaction) error

// Transactor provides transaction management.
type Transactor interface {
	WithTransaction(ctx context.Context, fn TxFunc) error
}

// HealthChecker provides database health checks.
type HealthChecker interface {
	Ping(ctx context.Context) error
	IsHealthy(ctx context.Context) bool
}

// Migrator handles database migrations.
type Migrator interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Version(ctx context.Context) (int, error)
}

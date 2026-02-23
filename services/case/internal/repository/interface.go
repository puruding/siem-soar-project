// Package repository provides data access layer for cases.
package repository

import (
	"context"

	"github.com/siem-soar-platform/services/case/internal/model"
)

// Repository defines the interface for case data operations.
type Repository interface {
	Create(ctx context.Context, caseObj *model.Case) error
	Get(ctx context.Context, id string) (*model.Case, error)
	Update(ctx context.Context, caseObj *model.Case) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter *model.CaseFilter) (*model.CaseListResult, error)
	GetSummary(ctx context.Context, tenantID string) (*model.CaseSummary, error)
	AddHistory(ctx context.Context, history *model.CaseHistory) error
	GetHistory(ctx context.Context, caseID string, limit int) ([]*model.CaseHistory, error)
}

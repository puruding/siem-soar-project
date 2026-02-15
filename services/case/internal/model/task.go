// Package model provides task model definitions.
package model

import (
	"time"
)

// TaskStatus represents task status values.
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusInProgress TaskStatus = "in_progress"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusCancelled  TaskStatus = "cancelled"
	TaskStatusBlocked    TaskStatus = "blocked"
)

// TaskPriority represents task priority levels.
type TaskPriority string

const (
	TaskPriorityLow    TaskPriority = "low"
	TaskPriorityMedium TaskPriority = "medium"
	TaskPriorityHigh   TaskPriority = "high"
	TaskPriorityCritical TaskPriority = "critical"
)

// TaskCategory represents task category types.
type TaskCategory string

const (
	TaskCategoryInvestigation TaskCategory = "investigation"
	TaskCategoryContainment   TaskCategory = "containment"
	TaskCategoryEradication   TaskCategory = "eradication"
	TaskCategoryRecovery      TaskCategory = "recovery"
	TaskCategoryLessonsLearned TaskCategory = "lessons_learned"
	TaskCategoryDocumentation TaskCategory = "documentation"
	TaskCategoryNotification  TaskCategory = "notification"
	TaskCategoryOther         TaskCategory = "other"
)

// Task represents a task associated with a case.
type Task struct {
	ID          string       `json:"id" db:"id"`
	CaseID      string       `json:"case_id" db:"case_id"`
	Title       string       `json:"title" db:"title"`
	Description string       `json:"description,omitempty" db:"description"`
	Status      TaskStatus   `json:"status" db:"status"`
	Priority    TaskPriority `json:"priority" db:"priority"`
	Category    TaskCategory `json:"category" db:"category"`

	// Assignment
	Assignee      string `json:"assignee,omitempty" db:"assignee"`
	AssigneeName  string `json:"assignee_name,omitempty" db:"assignee_name"`
	AssigneeEmail string `json:"assignee_email,omitempty" db:"assignee_email"`

	// Timing
	DueDate     *time.Time `json:"due_date,omitempty" db:"due_date"`
	StartedAt   *time.Time `json:"started_at,omitempty" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	EstimatedMinutes int   `json:"estimated_minutes,omitempty" db:"estimated_minutes"`
	ActualMinutes    int   `json:"actual_minutes,omitempty" db:"actual_minutes"`

	// Playbook integration
	PlaybookID    string `json:"playbook_id,omitempty" db:"playbook_id"`
	PlaybookStep  string `json:"playbook_step,omitempty" db:"playbook_step"`
	ExecutionID   string `json:"execution_id,omitempty" db:"execution_id"`
	IsAutomated   bool   `json:"is_automated" db:"is_automated"`
	AutomationStatus string `json:"automation_status,omitempty" db:"automation_status"`

	// Dependencies
	DependsOn   []string `json:"depends_on,omitempty"`
	BlockedBy   []string `json:"blocked_by,omitempty"`

	// Result
	Result        string `json:"result,omitempty" db:"result"`
	ResultNotes   string `json:"result_notes,omitempty" db:"result_notes"`
	CompletedBy   string `json:"completed_by,omitempty" db:"completed_by"`

	// Checklist
	Checklist     []ChecklistItem `json:"checklist,omitempty"`
	ChecklistDone int             `json:"checklist_done" db:"checklist_done"`
	ChecklistTotal int            `json:"checklist_total" db:"checklist_total"`

	// Tags
	Tags   []string          `json:"tags,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy string    `json:"created_by" db:"created_by"`
	UpdatedBy string    `json:"updated_by,omitempty" db:"updated_by"`

	// Multi-tenancy
	TenantID string `json:"tenant_id,omitempty" db:"tenant_id"`
}

// ChecklistItem represents an item in a task checklist.
type ChecklistItem struct {
	ID          string     `json:"id"`
	Text        string     `json:"text"`
	Done        bool       `json:"done"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	CompletedBy string     `json:"completed_by,omitempty"`
}

// CreateTaskRequest represents a request to create a task.
type CreateTaskRequest struct {
	Title            string        `json:"title" validate:"required,min=1,max=500"`
	Description      string        `json:"description,omitempty"`
	Priority         TaskPriority  `json:"priority" validate:"required"`
	Category         TaskCategory  `json:"category" validate:"required"`
	Assignee         string        `json:"assignee,omitempty"`
	DueDate          *time.Time    `json:"due_date,omitempty"`
	EstimatedMinutes int           `json:"estimated_minutes,omitempty"`
	DependsOn        []string      `json:"depends_on,omitempty"`
	Checklist        []string      `json:"checklist,omitempty"` // List of checklist item texts
	Tags             []string      `json:"tags,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
}

// UpdateTaskRequest represents a request to update a task.
type UpdateTaskRequest struct {
	Title            *string       `json:"title,omitempty"`
	Description      *string       `json:"description,omitempty"`
	Status           *TaskStatus   `json:"status,omitempty"`
	Priority         *TaskPriority `json:"priority,omitempty"`
	Category         *TaskCategory `json:"category,omitempty"`
	Assignee         *string       `json:"assignee,omitempty"`
	DueDate          *time.Time    `json:"due_date,omitempty"`
	EstimatedMinutes *int          `json:"estimated_minutes,omitempty"`
	ActualMinutes    *int          `json:"actual_minutes,omitempty"`
	Result           *string       `json:"result,omitempty"`
	ResultNotes      *string       `json:"result_notes,omitempty"`
	Tags             []string      `json:"tags,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
}

// TaskFilter defines filters for listing tasks.
type TaskFilter struct {
	CaseID   string         `json:"case_id,omitempty"`
	Status   []TaskStatus   `json:"status,omitempty"`
	Priority []TaskPriority `json:"priority,omitempty"`
	Category []TaskCategory `json:"category,omitempty"`
	Assignee string         `json:"assignee,omitempty"`
	Overdue  *bool          `json:"overdue,omitempty"`
	Search   string         `json:"search,omitempty"`
	Limit    int            `json:"limit,omitempty"`
	Offset   int            `json:"offset,omitempty"`
}

// TaskListResult contains paginated task results.
type TaskListResult struct {
	Tasks   []*Task `json:"tasks"`
	Total   int64   `json:"total"`
	Limit   int     `json:"limit"`
	Offset  int     `json:"offset"`
	HasMore bool    `json:"has_more"`
}

// Comment represents a comment on a case.
type Comment struct {
	ID         string    `json:"id" db:"id"`
	CaseID     string    `json:"case_id" db:"case_id"`
	ParentID   string    `json:"parent_id,omitempty" db:"parent_id"` // For threaded comments
	Content    string    `json:"content" db:"content"`
	ContentType string   `json:"content_type" db:"content_type"` // text, markdown
	Author     string    `json:"author" db:"author"`
	AuthorName string    `json:"author_name,omitempty" db:"author_name"`
	AuthorEmail string   `json:"author_email,omitempty" db:"author_email"`
	IsInternal bool      `json:"is_internal" db:"is_internal"` // Internal vs external visibility
	Mentions   []string  `json:"mentions,omitempty"` // @mentioned users
	Attachments []string `json:"attachments,omitempty"` // Evidence IDs
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
	EditedAt   *time.Time `json:"edited_at,omitempty" db:"edited_at"`
	TenantID   string    `json:"tenant_id,omitempty" db:"tenant_id"`
}

// CreateCommentRequest represents a request to add a comment.
type CreateCommentRequest struct {
	Content     string   `json:"content" validate:"required,min=1"`
	ContentType string   `json:"content_type,omitempty"` // defaults to "text"
	ParentID    string   `json:"parent_id,omitempty"`
	IsInternal  bool     `json:"is_internal,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
}

// UpdateCommentRequest represents a request to update a comment.
type UpdateCommentRequest struct {
	Content *string `json:"content,omitempty"`
}

// CommentFilter defines filters for listing comments.
type CommentFilter struct {
	CaseID     string `json:"case_id,omitempty"`
	Author     string `json:"author,omitempty"`
	IsInternal *bool  `json:"is_internal,omitempty"`
	Search     string `json:"search,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// CommentListResult contains paginated comment results.
type CommentListResult struct {
	Comments []*Comment `json:"comments"`
	Total    int64      `json:"total"`
	Limit    int        `json:"limit"`
	Offset   int        `json:"offset"`
	HasMore  bool       `json:"has_more"`
}

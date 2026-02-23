-- ============================================================================
-- SIEM-SOAR Platform: SOAR Executions Table for Persistent Storage
-- ============================================================================
-- Migration: 000010_soar_executions
-- Purpose: Store SOAR playbook execution history in PostgreSQL
-- Note: This enables execution history to persist across service restarts
-- ============================================================================

-- ============================================================================
-- SOAR Executions Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.executions (
    -- Primary Key
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Multi-tenant support
    tenant_id VARCHAR(64) NOT NULL,

    -- Playbook reference
    playbook_id TEXT NOT NULL,
    playbook_name VARCHAR(255) NOT NULL,
    playbook_version INTEGER DEFAULT 1,

    -- Execution status
    -- Values: pending, running, completed, failed, cancelled, timed_out, waiting_approval, paused
    status VARCHAR(32) NOT NULL DEFAULT 'pending',

    -- Temporal workflow integration
    workflow_id VARCHAR(255),
    run_id VARCHAR(255),

    -- Trigger information
    trigger_type VARCHAR(32) NOT NULL DEFAULT 'manual',
    -- Values: manual, automatic, scheduled, webhook, alert, incident
    trigger_info JSONB DEFAULT '{}',

    -- Related entities
    alert_id UUID,
    case_id UUID,

    -- Execution inputs and outputs
    inputs JSONB DEFAULT '{}',
    outputs JSONB DEFAULT '{}',

    -- Execution progress
    current_step VARCHAR(255),
    step_results JSONB DEFAULT '[]',

    -- Error information
    error TEXT,

    -- Audit metadata
    executed_by VARCHAR(255),
    trace_id VARCHAR(64),

    -- Timestamps
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- Indexes for efficient querying
-- ============================================================================

-- Tenant-based filtering
CREATE INDEX IF NOT EXISTS idx_soar_executions_tenant
    ON soar.executions(tenant_id);

-- Playbook-based filtering
CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook
    ON soar.executions(playbook_id);

-- Alert-based filtering (partial index for non-null values)
CREATE INDEX IF NOT EXISTS idx_soar_executions_alert
    ON soar.executions(alert_id)
    WHERE alert_id IS NOT NULL;

-- Case-based filtering (partial index for non-null values)
CREATE INDEX IF NOT EXISTS idx_soar_executions_case
    ON soar.executions(case_id)
    WHERE case_id IS NOT NULL;

-- Status-based filtering
CREATE INDEX IF NOT EXISTS idx_soar_executions_status
    ON soar.executions(status);

-- Temporal workflow lookup (partial index for non-null values)
CREATE INDEX IF NOT EXISTS idx_soar_executions_workflow
    ON soar.executions(workflow_id)
    WHERE workflow_id IS NOT NULL;

-- Time-based ordering (descending for recent-first queries)
CREATE INDEX IF NOT EXISTS idx_soar_executions_created
    ON soar.executions(created_at DESC);

-- Compound index for common query patterns
CREATE INDEX IF NOT EXISTS idx_soar_executions_tenant_status
    ON soar.executions(tenant_id, status, created_at DESC);

-- ============================================================================
-- Trigger for auto-updating updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION soar.update_execution_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soar_executions_updated ON soar.executions;
CREATE TRIGGER trg_soar_executions_updated
    BEFORE UPDATE ON soar.executions
    FOR EACH ROW
    EXECUTE FUNCTION soar.update_execution_timestamp();

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE soar.executions IS 'SOAR playbook execution history with persistent storage';
COMMENT ON COLUMN soar.executions.id IS 'Unique execution identifier (UUID)';
COMMENT ON COLUMN soar.executions.playbook_id IS 'Reference to playbook (TEXT format: PB-{timestamp})';
COMMENT ON COLUMN soar.executions.status IS 'Execution status: pending, running, completed, failed, cancelled, timed_out, waiting_approval, paused';
COMMENT ON COLUMN soar.executions.workflow_id IS 'Temporal workflow ID for distributed execution';
COMMENT ON COLUMN soar.executions.trigger_type IS 'How the execution was triggered: manual, automatic, scheduled, webhook, alert, incident';
COMMENT ON COLUMN soar.executions.step_results IS 'JSONB array of step execution results';
COMMENT ON COLUMN soar.executions.trace_id IS 'Distributed tracing correlation ID';

-- ============================================================================
-- SIEM-SOAR Platform: Playbooks & Automation Migration
-- ============================================================================
-- Migration: 000006_playbooks
-- Purpose: SOAR playbooks, actions, and automation workflows
-- ============================================================================

-- ============================================================================
-- Playbook Status Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE soar.playbook_status AS ENUM (
        'DRAFT',
        'TESTING',
        'ACTIVE',
        'DISABLED',
        'DEPRECATED'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Execution Status Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE soar.execution_status AS ENUM (
        'PENDING',
        'RUNNING',
        'AWAITING_INPUT',
        'AWAITING_APPROVAL',
        'COMPLETED',
        'FAILED',
        'CANCELLED',
        'TIMED_OUT',
        'SKIPPED'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Playbooks Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(100),  -- enrichment, containment, remediation, notification, etc.

    -- Version control
    version INTEGER DEFAULT 1,
    version_notes TEXT,
    is_latest BOOLEAN DEFAULT TRUE,

    -- Definition
    definition JSONB NOT NULL,  -- Workflow definition (nodes, edges, conditions)
    trigger_config JSONB,  -- Trigger configuration (alert conditions, schedules)

    -- Trigger types
    trigger_type VARCHAR(50) DEFAULT 'MANUAL',  -- MANUAL, ALERT, SCHEDULE, WEBHOOK, EVENT
    trigger_conditions JSONB,  -- Conditions for automatic trigger

    -- Settings
    timeout_minutes INTEGER DEFAULT 60,
    max_retries INTEGER DEFAULT 3,
    retry_delay_seconds INTEGER DEFAULT 30,
    run_mode VARCHAR(20) DEFAULT 'SEQUENTIAL',  -- SEQUENTIAL, PARALLEL

    -- Approval settings
    requires_approval BOOLEAN DEFAULT FALSE,
    approval_config JSONB DEFAULT '{
        "approvers": [],
        "min_approvers": 1,
        "timeout_hours": 24,
        "auto_approve_severity": null
    }'::JSONB,

    -- Status
    status soar.playbook_status DEFAULT 'DRAFT',
    is_enabled BOOLEAN DEFAULT FALSE,
    is_system BOOLEAN DEFAULT FALSE,

    -- Statistics
    execution_count BIGINT DEFAULT 0,
    success_count BIGINT DEFAULT 0,
    failure_count BIGINT DEFAULT 0,
    avg_duration_ms FLOAT,
    last_executed_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,

    -- Tags
    tags TEXT[],
    labels JSONB DEFAULT '{}'::JSONB,

    -- MITRE mapping (what this playbook addresses)
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],

    -- Related rules (auto-trigger from these rules)
    trigger_rules UUID[],

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,
    published_at TIMESTAMPTZ,
    published_by UUID,

    CONSTRAINT playbooks_name_tenant_unique UNIQUE (tenant_id, name, version)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant ON soar.playbooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_playbooks_status ON soar.playbooks(status);
CREATE INDEX IF NOT EXISTS idx_playbooks_category ON soar.playbooks(category);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON soar.playbooks(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_type ON soar.playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_playbooks_tags ON soar.playbooks USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_rules ON soar.playbooks USING GIN (trigger_rules);

-- Full-text search
CREATE INDEX IF NOT EXISTS idx_playbooks_search ON soar.playbooks
    USING GIN (to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, '')));

-- Trigger for updated_at
CREATE TRIGGER update_playbooks_updated_at
    BEFORE UPDATE ON soar.playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Connectors (Integration Plugins)
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.connectors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    connector_type VARCHAR(100) NOT NULL,  -- active_directory, crowdstrike, splunk, jira, etc.
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,

    -- Connector info
    vendor VARCHAR(100),
    product VARCHAR(100),
    version VARCHAR(50),
    icon_url VARCHAR(500),

    -- Configuration
    config JSONB NOT NULL,  -- Connection settings (encrypted sensitive fields)

    -- Authentication
    auth_type VARCHAR(50),  -- api_key, oauth2, basic, certificate, etc.
    credentials JSONB,  -- Encrypted credentials

    -- Endpoints (for REST connectors)
    base_url VARCHAR(500),
    health_check_endpoint VARCHAR(255),

    -- Status
    status entity_status DEFAULT 'ACTIVE',
    is_enabled BOOLEAN DEFAULT TRUE,
    is_system BOOLEAN DEFAULT FALSE,
    health_status VARCHAR(20) DEFAULT 'UNKNOWN',  -- HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
    last_health_check TIMESTAMPTZ,
    last_error TEXT,

    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 60,
    rate_limit_remaining INTEGER,
    rate_limit_reset_at TIMESTAMPTZ,

    -- Statistics
    call_count BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    avg_response_ms FLOAT,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT connectors_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON soar.connectors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_connectors_type ON soar.connectors(connector_type);
CREATE INDEX IF NOT EXISTS idx_connectors_enabled ON soar.connectors(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_connectors_health ON soar.connectors(health_status);

-- Trigger for updated_at
CREATE TRIGGER update_connectors_updated_at
    BEFORE UPDATE ON soar.connectors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Connector Actions (Available Operations)
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.connector_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Link to connector type (not instance)
    connector_type VARCHAR(100) NOT NULL,

    -- Action definition
    action_name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(50),  -- enrichment, containment, notification, etc.

    -- Parameters schema
    input_schema JSONB NOT NULL,  -- JSON Schema for inputs
    output_schema JSONB,  -- JSON Schema for outputs

    -- Execution settings
    is_blocking BOOLEAN DEFAULT TRUE,  -- Wait for result
    timeout_seconds INTEGER DEFAULT 30,
    is_idempotent BOOLEAN DEFAULT TRUE,

    -- Risk level
    risk_level VARCHAR(20) DEFAULT 'LOW',  -- LOW, MEDIUM, HIGH, CRITICAL
    requires_approval BOOLEAN DEFAULT FALSE,

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Documentation
    documentation_url VARCHAR(500),
    examples JSONB,

    CONSTRAINT connector_actions_unique UNIQUE (connector_type, action_name)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_connector_actions_type ON soar.connector_actions(connector_type);
CREATE INDEX IF NOT EXISTS idx_connector_actions_category ON soar.connector_actions(category);

-- ============================================================================
-- Playbook Executions
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.playbook_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,
    playbook_id UUID NOT NULL REFERENCES soar.playbooks(id),

    -- Execution context
    trigger_type VARCHAR(50) NOT NULL,  -- MANUAL, ALERT, SCHEDULE, WEBHOOK
    triggered_by UUID REFERENCES auth.users(id),
    trigger_source VARCHAR(255),

    -- Related entities
    case_id UUID REFERENCES soar.cases(id),
    alert_id UUID,  -- ClickHouse alert ID
    alert_ids UUID[],  -- Multiple alerts

    -- Input/Output
    input_data JSONB,
    output_data JSONB,
    variables JSONB DEFAULT '{}'::JSONB,  -- Runtime variables

    -- Status
    status soar.execution_status DEFAULT 'PENDING',
    error_message TEXT,
    error_details JSONB,

    -- Progress
    total_steps INTEGER DEFAULT 0,
    completed_steps INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    progress_percent FLOAT DEFAULT 0,

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,

    -- Approval tracking
    approval_status VARCHAR(20),  -- PENDING, APPROVED, REJECTED
    approved_by UUID REFERENCES auth.users(id),
    approved_at TIMESTAMPTZ,
    approval_notes TEXT,

    -- Retry info
    retry_count INTEGER DEFAULT 0,
    parent_execution_id UUID REFERENCES soar.playbook_executions(id),

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_playbook_executions_tenant ON soar.playbook_executions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_playbook ON soar.playbook_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_status ON soar.playbook_executions(status);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_case ON soar.playbook_executions(case_id);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_alert ON soar.playbook_executions(alert_id);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_started ON soar.playbook_executions(started_at);
CREATE INDEX IF NOT EXISTS idx_playbook_executions_running ON soar.playbook_executions(status)
    WHERE status IN ('PENDING', 'RUNNING', 'AWAITING_INPUT', 'AWAITING_APPROVAL');

-- Trigger for updated_at
CREATE TRIGGER update_playbook_executions_updated_at
    BEFORE UPDATE ON soar.playbook_executions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Playbook Step Executions
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.playbook_step_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES soar.playbook_executions(id) ON DELETE CASCADE,

    -- Step info
    step_id VARCHAR(100) NOT NULL,
    step_name VARCHAR(255),
    step_type VARCHAR(50) NOT NULL,  -- action, condition, loop, parallel, human_input, approval

    -- Connector action (if applicable)
    connector_id UUID REFERENCES soar.connectors(id),
    action_name VARCHAR(100),

    -- Input/Output
    input_data JSONB,
    output_data JSONB,

    -- Status
    status soar.execution_status DEFAULT 'PENDING',
    error_message TEXT,
    error_code VARCHAR(50),

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,

    -- Retry info
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,

    -- Order
    sequence_number INTEGER,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_step_executions_execution ON soar.playbook_step_executions(execution_id);
CREATE INDEX IF NOT EXISTS idx_step_executions_status ON soar.playbook_step_executions(status);
CREATE INDEX IF NOT EXISTS idx_step_executions_step ON soar.playbook_step_executions(step_id);
CREATE INDEX IF NOT EXISTS idx_step_executions_connector ON soar.playbook_step_executions(connector_id);

-- ============================================================================
-- Action Log (Detailed execution history)
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.action_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Execution context
    execution_id UUID REFERENCES soar.playbook_executions(id),
    step_execution_id UUID REFERENCES soar.playbook_step_executions(id),

    -- Action details
    action_type VARCHAR(100) NOT NULL,
    action_name VARCHAR(255),
    connector_id UUID REFERENCES soar.connectors(id),
    connector_type VARCHAR(100),

    -- Target
    target_type VARCHAR(50),  -- host, user, ip, file, etc.
    target_value VARCHAR(500),

    -- Request/Response
    request_data JSONB,
    response_data JSONB,
    response_code INTEGER,

    -- Status
    status VARCHAR(20) NOT NULL,  -- SUCCESS, FAILURE, ERROR, TIMEOUT
    error_message TEXT,

    -- Timing
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,

    -- Actor
    triggered_by UUID REFERENCES auth.users(id),
    trigger_source VARCHAR(50),  -- PLAYBOOK, MANUAL, API

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_action_logs_tenant ON soar.action_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_execution ON soar.action_logs(execution_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_connector ON soar.action_logs(connector_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_action_type ON soar.action_logs(action_type);
CREATE INDEX IF NOT EXISTS idx_action_logs_status ON soar.action_logs(status);
CREATE INDEX IF NOT EXISTS idx_action_logs_started ON soar.action_logs(started_at);
CREATE INDEX IF NOT EXISTS idx_action_logs_target ON soar.action_logs(target_type, target_value);

-- ============================================================================
-- Scheduled Tasks
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.scheduled_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Task info
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Target (playbook or action)
    task_type VARCHAR(50) NOT NULL,  -- PLAYBOOK, ACTION
    playbook_id UUID REFERENCES soar.playbooks(id),
    action_config JSONB,

    -- Schedule (cron expression or interval)
    schedule_type VARCHAR(20) NOT NULL,  -- CRON, INTERVAL, ONCE
    cron_expression VARCHAR(100),
    interval_seconds INTEGER,
    run_at TIMESTAMPTZ,  -- For ONCE type
    timezone VARCHAR(50) DEFAULT 'UTC',

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    status entity_status DEFAULT 'ACTIVE',

    -- Execution history
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    last_run_duration_ms BIGINT,
    next_run_at TIMESTAMPTZ,
    run_count BIGINT DEFAULT 0,
    failure_count BIGINT DEFAULT 0,

    -- Error handling
    max_consecutive_failures INTEGER DEFAULT 3,
    consecutive_failures INTEGER DEFAULT 0,
    pause_on_failure BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT scheduled_tasks_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_tenant ON soar.scheduled_tasks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_enabled ON soar.scheduled_tasks(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_next_run ON soar.scheduled_tasks(next_run_at) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_playbook ON soar.scheduled_tasks(playbook_id);

-- Trigger for updated_at
CREATE TRIGGER update_scheduled_tasks_updated_at
    BEFORE UPDATE ON soar.scheduled_tasks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Approval Requests
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.approval_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Execution context
    execution_id UUID NOT NULL REFERENCES soar.playbook_executions(id) ON DELETE CASCADE,
    step_execution_id UUID REFERENCES soar.playbook_step_executions(id),

    -- Request details
    request_type VARCHAR(50) NOT NULL,  -- PLAYBOOK, ACTION, CASE
    title VARCHAR(255) NOT NULL,
    description TEXT,
    details JSONB,

    -- Risk assessment
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
    impact_description TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',  -- PENDING, APPROVED, REJECTED, EXPIRED
    decision_at TIMESTAMPTZ,
    decision_by UUID REFERENCES auth.users(id),
    decision_notes TEXT,

    -- Approvers
    requested_approvers UUID[],
    min_approvals INTEGER DEFAULT 1,
    approvals_received INTEGER DEFAULT 0,
    approval_responses JSONB DEFAULT '[]'::JSONB,

    -- Expiration
    expires_at TIMESTAMPTZ,
    is_expired BOOLEAN DEFAULT FALSE,

    -- Escalation
    escalated_at TIMESTAMPTZ,
    escalated_to UUID REFERENCES auth.users(id),

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    requested_by UUID REFERENCES auth.users(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_approval_requests_tenant ON soar.approval_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_execution ON soar.approval_requests(execution_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON soar.approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_pending ON soar.approval_requests(status, expires_at)
    WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_approval_requests_approvers ON soar.approval_requests USING GIN (requested_approvers);

-- Trigger for updated_at
CREATE TRIGGER update_approval_requests_updated_at
    BEFORE UPDATE ON soar.approval_requests
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Record migration
-- ============================================================================

INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000006', 'playbooks', md5('000006_playbooks'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE soar.playbooks IS 'SOAR playbook definitions';
COMMENT ON TABLE soar.connectors IS 'Integration connectors for external systems';
COMMENT ON TABLE soar.connector_actions IS 'Available actions for each connector type';
COMMENT ON TABLE soar.playbook_executions IS 'Playbook execution instances';
COMMENT ON TABLE soar.playbook_step_executions IS 'Individual step executions within a playbook';
COMMENT ON TABLE soar.action_logs IS 'Detailed log of all automated actions';
COMMENT ON TABLE soar.scheduled_tasks IS 'Scheduled playbook and action executions';
COMMENT ON TABLE soar.approval_requests IS 'Human-in-the-loop approval requests';

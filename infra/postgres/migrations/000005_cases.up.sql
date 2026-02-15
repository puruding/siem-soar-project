-- ============================================================================
-- SIEM-SOAR Platform: Cases & Incidents Migration
-- ============================================================================
-- Migration: 000005_cases
-- Purpose: Case management, incidents, and investigation tracking
-- ============================================================================

-- ============================================================================
-- Case Status Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE soar.case_status AS ENUM (
        'NEW',
        'TRIAGED',
        'IN_PROGRESS',
        'PENDING_INPUT',
        'PENDING_APPROVAL',
        'CONTAINED',
        'ERADICATED',
        'RECOVERED',
        'LESSONS_LEARNED',
        'CLOSED'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Case Priority Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE soar.case_priority AS ENUM (
        'P1_CRITICAL',
        'P2_HIGH',
        'P3_MEDIUM',
        'P4_LOW'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Case Type Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE soar.case_type AS ENUM (
        'INCIDENT',
        'INVESTIGATION',
        'THREAT_HUNT',
        'VULNERABILITY',
        'COMPLIANCE',
        'REQUEST',
        'OTHER'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Cases Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    case_number VARCHAR(20) NOT NULL,  -- Human-readable (e.g., INC-2024-0001)
    title VARCHAR(500) NOT NULL,
    summary TEXT,
    description TEXT,

    -- Classification
    case_type soar.case_type NOT NULL DEFAULT 'INCIDENT',
    category VARCHAR(100),  -- malware, phishing, data_breach, etc.
    subcategory VARCHAR(100),

    -- Severity & Priority
    severity severity_level DEFAULT 'MEDIUM',
    priority soar.case_priority DEFAULT 'P3_MEDIUM',
    impact VARCHAR(100),
    urgency VARCHAR(100),

    -- Status & Workflow
    status soar.case_status DEFAULT 'NEW',
    status_reason TEXT,
    resolution VARCHAR(100),  -- TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, etc.
    resolution_summary TEXT,

    -- Assignment
    assignee_id UUID REFERENCES auth.users(id),
    assignee_group_id UUID REFERENCES auth.user_groups(id),
    owner_id UUID REFERENCES auth.users(id),
    escalated_to UUID REFERENCES auth.users(id),
    escalation_count INTEGER DEFAULT 0,

    -- Timeline
    detected_at TIMESTAMPTZ,
    reported_at TIMESTAMPTZ,
    triaged_at TIMESTAMPTZ,
    contained_at TIMESTAMPTZ,
    eradicated_at TIMESTAMPTZ,
    recovered_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,

    -- SLA
    sla_response_due TIMESTAMPTZ,
    sla_resolution_due TIMESTAMPTZ,
    sla_response_met BOOLEAN,
    sla_resolution_met BOOLEAN,

    -- Scope & Impact
    affected_assets UUID[],
    affected_users UUID[],
    affected_systems TEXT[],
    data_classification VARCHAR(50),
    data_compromised BOOLEAN DEFAULT FALSE,
    pii_involved BOOLEAN DEFAULT FALSE,
    regulatory_impact TEXT[],  -- GDPR, HIPAA, PCI, etc.

    -- Attack Details
    attack_vector VARCHAR(100),
    attack_stage VARCHAR(100),  -- MITRE: Initial Access, Execution, etc.
    malware_families TEXT[],
    threat_actors TEXT[],
    campaigns TEXT[],

    -- MITRE ATT&CK
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],

    -- Related Items
    related_cases UUID[],
    parent_case_id UUID REFERENCES soar.cases(id),
    child_cases UUID[],
    alert_count INTEGER DEFAULT 0,
    event_count BIGINT DEFAULT 0,

    -- External References
    external_ticket_id VARCHAR(100),
    external_ticket_url VARCHAR(500),
    ticket_system VARCHAR(50),  -- jira, servicenow, etc.

    -- Tags & Labels
    tags TEXT[],
    labels JSONB DEFAULT '{}'::JSONB,

    -- Custom Fields
    custom_fields JSONB DEFAULT '{}'::JSONB,

    -- Metrics
    time_to_detect_minutes INTEGER,
    time_to_contain_minutes INTEGER,
    time_to_resolve_minutes INTEGER,
    total_work_hours FLOAT DEFAULT 0,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES auth.users(id),
    updated_by UUID REFERENCES auth.users(id),

    CONSTRAINT cases_number_tenant_unique UNIQUE (tenant_id, case_number)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cases_tenant ON soar.cases(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON soar.cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_priority ON soar.cases(priority);
CREATE INDEX IF NOT EXISTS idx_cases_severity ON soar.cases(severity);
CREATE INDEX IF NOT EXISTS idx_cases_assignee ON soar.cases(assignee_id);
CREATE INDEX IF NOT EXISTS idx_cases_owner ON soar.cases(owner_id);
CREATE INDEX IF NOT EXISTS idx_cases_case_type ON soar.cases(case_type);
CREATE INDEX IF NOT EXISTS idx_cases_created ON soar.cases(created_at);
CREATE INDEX IF NOT EXISTS idx_cases_sla_response ON soar.cases(sla_response_due) WHERE status NOT IN ('CLOSED', 'RECOVERED');
CREATE INDEX IF NOT EXISTS idx_cases_tags ON soar.cases USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_cases_mitre ON soar.cases USING GIN (mitre_techniques);

-- Full-text search
CREATE INDEX IF NOT EXISTS idx_cases_search ON soar.cases
    USING GIN (to_tsvector('english', coalesce(title, '') || ' ' || coalesce(summary, '') || ' ' || coalesce(description, '')));

-- Trigger for updated_at
CREATE TRIGGER update_cases_updated_at
    BEFORE UPDATE ON soar.cases
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Case Alerts (Linked Alerts)
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.case_alerts (
    case_id UUID NOT NULL REFERENCES soar.cases(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL,  -- References ClickHouse alert

    -- Link metadata
    linked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    linked_by UUID REFERENCES auth.users(id),
    link_reason TEXT,

    -- Status
    is_root_cause BOOLEAN DEFAULT FALSE,
    is_false_positive BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'LINKED',

    -- Notes
    analyst_notes TEXT,

    PRIMARY KEY (case_id, alert_id)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON soar.case_alerts(alert_id);

-- ============================================================================
-- Case Evidence
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.case_evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES soar.cases(id) ON DELETE CASCADE,

    -- Evidence details
    evidence_type VARCHAR(50) NOT NULL,  -- file, screenshot, log, email, network_capture, memory_dump, etc.
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- File details (if applicable)
    file_name VARCHAR(255),
    file_path VARCHAR(500),
    file_size BIGINT,
    file_hash_md5 VARCHAR(32),
    file_hash_sha256 VARCHAR(64),
    mime_type VARCHAR(100),

    -- Content (for small text evidence)
    content TEXT,

    -- Storage
    storage_type VARCHAR(50) DEFAULT 'S3',  -- S3, local, database
    storage_path VARCHAR(500),
    storage_bucket VARCHAR(255),

    -- Chain of custody
    collected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    collected_by UUID REFERENCES auth.users(id),
    collection_source VARCHAR(255),
    collection_method VARCHAR(100),

    -- Integrity
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    verified_by UUID REFERENCES auth.users(id),

    -- Tags
    tags TEXT[],

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON soar.case_evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_case_evidence_type ON soar.case_evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_case_evidence_hash ON soar.case_evidence(file_hash_sha256) WHERE file_hash_sha256 IS NOT NULL;

-- ============================================================================
-- Case Timeline (Activity Log)
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.case_timeline (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES soar.cases(id) ON DELETE CASCADE,

    -- Event details
    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50) NOT NULL,  -- status_change, assignment, note, evidence, alert_linked, playbook_run, etc.
    event_source VARCHAR(50) DEFAULT 'USER',  -- USER, SYSTEM, PLAYBOOK, AI

    -- Content
    title VARCHAR(255) NOT NULL,
    description TEXT,
    details JSONB DEFAULT '{}'::JSONB,

    -- Changes (for status/field changes)
    field_changed VARCHAR(100),
    old_value TEXT,
    new_value TEXT,

    -- Related items
    related_alert_id UUID,
    related_evidence_id UUID REFERENCES soar.case_evidence(id),
    related_playbook_execution_id UUID,

    -- Actor
    actor_id UUID REFERENCES auth.users(id),
    actor_name VARCHAR(255),
    actor_type VARCHAR(50) DEFAULT 'USER',  -- USER, SYSTEM, PLAYBOOK, AI

    -- Visibility
    is_internal BOOLEAN DEFAULT FALSE,
    is_customer_visible BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_case_timeline_case ON soar.case_timeline(case_id);
CREATE INDEX IF NOT EXISTS idx_case_timeline_time ON soar.case_timeline(event_time);
CREATE INDEX IF NOT EXISTS idx_case_timeline_type ON soar.case_timeline(event_type);
CREATE INDEX IF NOT EXISTS idx_case_timeline_actor ON soar.case_timeline(actor_id);

-- ============================================================================
-- Case Comments
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.case_comments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES soar.cases(id) ON DELETE CASCADE,

    -- Comment content
    content TEXT NOT NULL,
    content_html TEXT,  -- Rich text HTML version

    -- Reply threading
    parent_comment_id UUID REFERENCES soar.case_comments(id),
    reply_count INTEGER DEFAULT 0,

    -- Mentions
    mentioned_users UUID[],

    -- Attachments
    attachments JSONB DEFAULT '[]'::JSONB,

    -- Visibility
    is_internal BOOLEAN DEFAULT FALSE,
    is_pinned BOOLEAN DEFAULT FALSE,

    -- Status
    is_edited BOOLEAN DEFAULT FALSE,
    edited_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES auth.users(id),

    -- Reactions
    reactions JSONB DEFAULT '{}'::JSONB  -- {"thumbsup": [user_ids], "resolved": [user_ids]}
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_case_comments_case ON soar.case_comments(case_id);
CREATE INDEX IF NOT EXISTS idx_case_comments_parent ON soar.case_comments(parent_comment_id);
CREATE INDEX IF NOT EXISTS idx_case_comments_created ON soar.case_comments(created_at);
CREATE INDEX IF NOT EXISTS idx_case_comments_author ON soar.case_comments(created_by);

-- Trigger for updated_at
CREATE TRIGGER update_case_comments_updated_at
    BEFORE UPDATE ON soar.case_comments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Case Tasks (Checklist)
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.case_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID NOT NULL REFERENCES soar.cases(id) ON DELETE CASCADE,

    -- Task details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    task_type VARCHAR(50) DEFAULT 'MANUAL',  -- MANUAL, AUTOMATED, APPROVAL

    -- Status
    status VARCHAR(50) DEFAULT 'PENDING',  -- PENDING, IN_PROGRESS, COMPLETED, SKIPPED, BLOCKED
    completed_at TIMESTAMPTZ,

    -- Assignment
    assignee_id UUID REFERENCES auth.users(id),
    due_date TIMESTAMPTZ,
    is_overdue BOOLEAN DEFAULT FALSE,

    -- Order & Dependencies
    sort_order INTEGER DEFAULT 0,
    depends_on UUID[],

    -- Automated task config
    playbook_id UUID,
    playbook_action VARCHAR(100),
    automation_config JSONB,
    automation_result JSONB,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES auth.users(id),
    completed_by UUID REFERENCES auth.users(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_case_tasks_case ON soar.case_tasks(case_id);
CREATE INDEX IF NOT EXISTS idx_case_tasks_status ON soar.case_tasks(status);
CREATE INDEX IF NOT EXISTS idx_case_tasks_assignee ON soar.case_tasks(assignee_id);
CREATE INDEX IF NOT EXISTS idx_case_tasks_due ON soar.case_tasks(due_date) WHERE status NOT IN ('COMPLETED', 'SKIPPED');

-- Trigger for updated_at
CREATE TRIGGER update_case_tasks_updated_at
    BEFORE UPDATE ON soar.case_tasks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Case Templates
-- ============================================================================

CREATE TABLE IF NOT EXISTS soar.case_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Template content
    case_type soar.case_type NOT NULL,
    category VARCHAR(100),
    default_severity severity_level DEFAULT 'MEDIUM',
    default_priority soar.case_priority DEFAULT 'P3_MEDIUM',

    -- Template fields
    title_template VARCHAR(500),
    description_template TEXT,
    summary_template TEXT,

    -- Tasks template
    task_templates JSONB DEFAULT '[]'::JSONB,

    -- Playbooks to auto-run
    auto_playbooks UUID[],

    -- Tags
    default_tags TEXT[],

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    is_system BOOLEAN DEFAULT FALSE,

    -- Usage
    use_count INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT case_templates_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_case_templates_tenant ON soar.case_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_case_templates_type ON soar.case_templates(case_type);
CREATE INDEX IF NOT EXISTS idx_case_templates_enabled ON soar.case_templates(is_enabled) WHERE is_enabled = TRUE;

-- ============================================================================
-- Generate case number function
-- ============================================================================

CREATE OR REPLACE FUNCTION soar.generate_case_number(p_tenant_id UUID, p_prefix VARCHAR DEFAULT 'INC')
RETURNS VARCHAR AS $$
DECLARE
    v_year VARCHAR(4);
    v_sequence INTEGER;
    v_case_number VARCHAR(20);
BEGIN
    v_year := to_char(CURRENT_DATE, 'YYYY');

    -- Get next sequence number for this tenant/year
    SELECT COALESCE(MAX(
        CASE
            WHEN case_number ~ ('^' || p_prefix || '-' || v_year || '-[0-9]+$')
            THEN CAST(split_part(case_number, '-', 3) AS INTEGER)
            ELSE 0
        END
    ), 0) + 1
    INTO v_sequence
    FROM soar.cases
    WHERE tenant_id = p_tenant_id
      AND case_number LIKE p_prefix || '-' || v_year || '-%';

    v_case_number := p_prefix || '-' || v_year || '-' || lpad(v_sequence::TEXT, 4, '0');
    RETURN v_case_number;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Record migration
-- ============================================================================

INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000005', 'cases', md5('000005_cases'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE soar.cases IS 'Security incidents and investigation cases';
COMMENT ON TABLE soar.case_alerts IS 'Links between cases and alerts';
COMMENT ON TABLE soar.case_evidence IS 'Evidence collected during investigation';
COMMENT ON TABLE soar.case_timeline IS 'Activity timeline for cases';
COMMENT ON TABLE soar.case_comments IS 'Discussion comments on cases';
COMMENT ON TABLE soar.case_tasks IS 'Checklist tasks for case workflows';
COMMENT ON TABLE soar.case_templates IS 'Templates for creating new cases';
COMMENT ON FUNCTION soar.generate_case_number IS 'Generates sequential case numbers';

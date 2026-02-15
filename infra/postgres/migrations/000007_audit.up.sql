-- ============================================================================
-- SIEM-SOAR Platform: Audit Logging Migration
-- ============================================================================
-- Migration: 000007_audit
-- Purpose: Comprehensive audit logging for compliance and security
-- ============================================================================

-- ============================================================================
-- Audit Action Categories
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE audit.action_category AS ENUM (
        'AUTH',           -- Authentication events
        'USER',           -- User management
        'TENANT',         -- Tenant management
        'CASE',           -- Case operations
        'ALERT',          -- Alert operations
        'RULE',           -- Rule management
        'PLAYBOOK',       -- Playbook operations
        'CONNECTOR',      -- Connector management
        'SEARCH',         -- Search/query operations
        'EXPORT',         -- Data export
        'CONFIG',         -- Configuration changes
        'API',            -- API access
        'ADMIN'           -- Administrative actions
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Audit Log Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES meta.tenants(id) ON DELETE SET NULL,

    -- Event identification
    event_id VARCHAR(100) NOT NULL,  -- Human-readable event type
    event_category audit.action_category NOT NULL,
    event_action VARCHAR(100) NOT NULL,  -- create, read, update, delete, execute, etc.
    event_outcome VARCHAR(20) NOT NULL,  -- SUCCESS, FAILURE, UNKNOWN

    -- Actor information
    actor_type VARCHAR(50) NOT NULL,  -- USER, SYSTEM, API, PLAYBOOK
    actor_id UUID,
    actor_email VARCHAR(255),
    actor_name VARCHAR(255),
    actor_ip INET,
    actor_user_agent TEXT,
    actor_session_id UUID,
    actor_api_key_id UUID,

    -- Target information
    target_type VARCHAR(100),  -- user, case, alert, rule, playbook, etc.
    target_id VARCHAR(255),
    target_name VARCHAR(255),

    -- Details
    description TEXT,
    details JSONB DEFAULT '{}'::JSONB,

    -- Changes (for update events)
    changes JSONB,  -- {"field": {"old": "x", "new": "y"}}

    -- Request context
    request_id VARCHAR(100),
    request_method VARCHAR(10),
    request_path VARCHAR(500),
    request_params JSONB,

    -- Location (from IP geolocation)
    geo_country VARCHAR(100),
    geo_city VARCHAR(100),

    -- Risk assessment
    risk_score INTEGER DEFAULT 0,  -- 0-100
    is_sensitive BOOLEAN DEFAULT FALSE,
    is_anomalous BOOLEAN DEFAULT FALSE,

    -- Retention
    retention_days INTEGER DEFAULT 365,

    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit.audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit.audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_category ON audit.audit_logs(event_category);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit.audit_logs(event_action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome ON audit.audit_logs(event_outcome);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit.audit_logs(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit.audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip ON audit.audit_logs(actor_ip);
CREATE INDEX IF NOT EXISTS idx_audit_logs_risk ON audit.audit_logs(risk_score) WHERE risk_score > 50;
CREATE INDEX IF NOT EXISTS idx_audit_logs_anomalous ON audit.audit_logs(is_anomalous) WHERE is_anomalous = TRUE;

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_time ON audit.audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_time ON audit.audit_logs(actor_id, created_at DESC);

-- Full-text search on description
CREATE INDEX IF NOT EXISTS idx_audit_logs_search ON audit.audit_logs
    USING GIN (to_tsvector('english', coalesce(description, '')));

-- ============================================================================
-- Login Audit (Specialized for auth events)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit.login_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES meta.tenants(id) ON DELETE SET NULL,

    -- User info
    user_id UUID,
    user_email VARCHAR(255) NOT NULL,
    username VARCHAR(100),

    -- Event
    event_type VARCHAR(50) NOT NULL,  -- LOGIN, LOGOUT, LOGIN_FAILED, MFA_CHALLENGE, PASSWORD_RESET, etc.
    outcome VARCHAR(20) NOT NULL,  -- SUCCESS, FAILURE

    -- Authentication details
    auth_method VARCHAR(50),  -- password, sso_saml, sso_oidc, api_key, mfa_totp
    sso_provider_id UUID,
    mfa_method VARCHAR(50),

    -- Failure details
    failure_reason VARCHAR(100),
    failure_count INTEGER DEFAULT 0,

    -- Client info
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_type VARCHAR(50),
    device_fingerprint VARCHAR(255),

    -- Location
    geo_country VARCHAR(100),
    geo_city VARCHAR(100),
    geo_latitude FLOAT,
    geo_longitude FLOAT,

    -- Session
    session_id UUID,
    session_duration_minutes INTEGER,

    -- Risk assessment
    is_suspicious BOOLEAN DEFAULT FALSE,
    risk_indicators TEXT[],
    risk_score INTEGER DEFAULT 0,

    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_login_audit_tenant ON audit.login_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_login_audit_user ON audit.login_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_login_audit_email ON audit.login_audit(user_email);
CREATE INDEX IF NOT EXISTS idx_login_audit_event ON audit.login_audit(event_type);
CREATE INDEX IF NOT EXISTS idx_login_audit_outcome ON audit.login_audit(outcome);
CREATE INDEX IF NOT EXISTS idx_login_audit_ip ON audit.login_audit(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_audit_created ON audit.login_audit(created_at);
CREATE INDEX IF NOT EXISTS idx_login_audit_suspicious ON audit.login_audit(is_suspicious) WHERE is_suspicious = TRUE;

-- Composite for failed login analysis
CREATE INDEX IF NOT EXISTS idx_login_audit_failed ON audit.login_audit(user_email, ip_address, created_at)
    WHERE outcome = 'FAILURE';

-- ============================================================================
-- API Audit (API access logging)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit.api_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES meta.tenants(id) ON DELETE SET NULL,

    -- Request identification
    request_id VARCHAR(100) NOT NULL,
    trace_id VARCHAR(100),

    -- Caller info
    caller_type VARCHAR(50) NOT NULL,  -- USER, API_KEY, SERVICE
    caller_id UUID,
    api_key_id UUID,
    api_key_name VARCHAR(255),

    -- Request details
    method VARCHAR(10) NOT NULL,
    path VARCHAR(500) NOT NULL,
    query_params JSONB,
    request_body_size INTEGER,
    request_content_type VARCHAR(100),

    -- Response details
    status_code INTEGER NOT NULL,
    response_body_size INTEGER,
    response_time_ms INTEGER,

    -- Rate limiting
    rate_limit_remaining INTEGER,
    rate_limit_reset_at TIMESTAMPTZ,

    -- Client info
    ip_address INET NOT NULL,
    user_agent TEXT,

    -- Error details (if applicable)
    error_code VARCHAR(50),
    error_message TEXT,

    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_api_audit_tenant ON audit.api_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_audit_caller ON audit.api_audit(caller_id);
CREATE INDEX IF NOT EXISTS idx_api_audit_api_key ON audit.api_audit(api_key_id);
CREATE INDEX IF NOT EXISTS idx_api_audit_path ON audit.api_audit(path);
CREATE INDEX IF NOT EXISTS idx_api_audit_status ON audit.api_audit(status_code);
CREATE INDEX IF NOT EXISTS idx_api_audit_created ON audit.api_audit(created_at);
CREATE INDEX IF NOT EXISTS idx_api_audit_ip ON audit.api_audit(ip_address);
CREATE INDEX IF NOT EXISTS idx_api_audit_errors ON audit.api_audit(status_code) WHERE status_code >= 400;

-- ============================================================================
-- Data Access Audit (Sensitive data access)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit.data_access_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES meta.tenants(id) ON DELETE SET NULL,

    -- Actor
    actor_id UUID NOT NULL,
    actor_email VARCHAR(255),
    actor_role VARCHAR(50),

    -- Access details
    access_type VARCHAR(50) NOT NULL,  -- VIEW, SEARCH, EXPORT, DOWNLOAD
    resource_type VARCHAR(100) NOT NULL,  -- event, alert, case, evidence, user_data
    resource_id VARCHAR(255),
    resource_name VARCHAR(255),

    -- Query details (for search operations)
    query_text TEXT,
    query_filters JSONB,
    time_range_start TIMESTAMPTZ,
    time_range_end TIMESTAMPTZ,

    -- Results
    result_count INTEGER,
    result_size_bytes BIGINT,

    -- Data classification
    data_classification VARCHAR(50),  -- PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    contains_pii BOOLEAN DEFAULT FALSE,
    pii_fields TEXT[],

    -- Export details (if applicable)
    export_format VARCHAR(50),
    export_destination VARCHAR(255),

    -- Context
    purpose TEXT,
    justification TEXT,

    -- Client info
    ip_address INET,
    user_agent TEXT,

    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_data_access_tenant ON audit.data_access_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_data_access_actor ON audit.data_access_audit(actor_id);
CREATE INDEX IF NOT EXISTS idx_data_access_type ON audit.data_access_audit(access_type);
CREATE INDEX IF NOT EXISTS idx_data_access_resource ON audit.data_access_audit(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_data_access_created ON audit.data_access_audit(created_at);
CREATE INDEX IF NOT EXISTS idx_data_access_pii ON audit.data_access_audit(contains_pii) WHERE contains_pii = TRUE;
CREATE INDEX IF NOT EXISTS idx_data_access_classification ON audit.data_access_audit(data_classification);

-- ============================================================================
-- Configuration Change Audit
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit.config_change_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES meta.tenants(id) ON DELETE SET NULL,

    -- Actor
    actor_id UUID NOT NULL,
    actor_email VARCHAR(255),

    -- Change details
    config_type VARCHAR(100) NOT NULL,  -- rule, playbook, connector, tenant_settings, etc.
    config_id VARCHAR(255),
    config_name VARCHAR(255),

    -- Change type
    change_type VARCHAR(50) NOT NULL,  -- CREATE, UPDATE, DELETE, ENABLE, DISABLE

    -- Change content
    previous_value JSONB,
    new_value JSONB,
    changed_fields TEXT[],
    change_summary TEXT,

    -- Approval (if required)
    required_approval BOOLEAN DEFAULT FALSE,
    approved_by UUID,
    approved_at TIMESTAMPTZ,

    -- Context
    reason TEXT,
    ticket_reference VARCHAR(100),

    -- Client info
    ip_address INET,

    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_config_change_tenant ON audit.config_change_audit(tenant_id);
CREATE INDEX IF NOT EXISTS idx_config_change_actor ON audit.config_change_audit(actor_id);
CREATE INDEX IF NOT EXISTS idx_config_change_type ON audit.config_change_audit(config_type);
CREATE INDEX IF NOT EXISTS idx_config_change_config ON audit.config_change_audit(config_type, config_id);
CREATE INDEX IF NOT EXISTS idx_config_change_created ON audit.config_change_audit(created_at);

-- ============================================================================
-- Audit Summary View (for dashboards)
-- ============================================================================

CREATE OR REPLACE VIEW audit.audit_summary_daily AS
SELECT
    DATE(created_at) AS date,
    tenant_id,
    event_category,
    event_action,
    event_outcome,
    COUNT(*) AS event_count,
    COUNT(DISTINCT actor_id) AS unique_actors,
    COUNT(CASE WHEN is_anomalous THEN 1 END) AS anomalous_count,
    AVG(risk_score) AS avg_risk_score
FROM audit.audit_logs
WHERE created_at >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY DATE(created_at), tenant_id, event_category, event_action, event_outcome;

-- ============================================================================
-- Audit log trigger function (for automatic logging)
-- ============================================================================

CREATE OR REPLACE FUNCTION audit.log_table_change()
RETURNS TRIGGER AS $$
DECLARE
    v_changes JSONB;
    v_old_data JSONB;
    v_new_data JSONB;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_old_data = row_to_json(OLD)::JSONB;
        v_new_data = NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old_data = row_to_json(OLD)::JSONB;
        v_new_data = row_to_json(NEW)::JSONB;
        -- Calculate changes
        SELECT jsonb_object_agg(key, jsonb_build_object('old', v_old_data->key, 'new', v_new_data->key))
        INTO v_changes
        FROM jsonb_object_keys(v_new_data) AS key
        WHERE v_old_data->key IS DISTINCT FROM v_new_data->key
          AND key NOT IN ('updated_at', 'version');  -- Exclude auto-updated fields
    ELSIF TG_OP = 'INSERT' THEN
        v_old_data = NULL;
        v_new_data = row_to_json(NEW)::JSONB;
    END IF;

    INSERT INTO audit.audit_logs (
        tenant_id,
        event_id,
        event_category,
        event_action,
        event_outcome,
        actor_type,
        actor_id,
        target_type,
        target_id,
        description,
        details,
        changes
    ) VALUES (
        COALESCE(
            CASE WHEN v_new_data ? 'tenant_id' THEN (v_new_data->>'tenant_id')::UUID ELSE NULL END,
            CASE WHEN v_old_data ? 'tenant_id' THEN (v_old_data->>'tenant_id')::UUID ELSE NULL END
        ),
        TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME || '.' || lower(TG_OP),
        'CONFIG'::audit.action_category,
        lower(TG_OP),
        'SUCCESS',
        'SYSTEM',
        COALESCE(
            CASE WHEN v_new_data ? 'updated_by' THEN (v_new_data->>'updated_by')::UUID ELSE NULL END,
            CASE WHEN v_new_data ? 'created_by' THEN (v_new_data->>'created_by')::UUID ELSE NULL END
        ),
        TG_TABLE_NAME,
        COALESCE(
            CASE WHEN v_new_data ? 'id' THEN v_new_data->>'id' ELSE NULL END,
            CASE WHEN v_old_data ? 'id' THEN v_old_data->>'id' ELSE NULL END
        ),
        TG_OP || ' on ' || TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
        jsonb_build_object(
            'operation', TG_OP,
            'table', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
            'old_data', v_old_data,
            'new_data', v_new_data
        ),
        v_changes
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- Apply audit triggers to critical tables
-- ============================================================================

-- Detection rules audit
DROP TRIGGER IF EXISTS audit_detection_rules ON meta.detection_rules;
CREATE TRIGGER audit_detection_rules
    AFTER INSERT OR UPDATE OR DELETE ON meta.detection_rules
    FOR EACH ROW EXECUTE FUNCTION audit.log_table_change();

-- Playbooks audit
DROP TRIGGER IF EXISTS audit_playbooks ON soar.playbooks;
CREATE TRIGGER audit_playbooks
    AFTER INSERT OR UPDATE OR DELETE ON soar.playbooks
    FOR EACH ROW EXECUTE FUNCTION audit.log_table_change();

-- Connectors audit
DROP TRIGGER IF EXISTS audit_connectors ON soar.connectors;
CREATE TRIGGER audit_connectors
    AFTER INSERT OR UPDATE OR DELETE ON soar.connectors
    FOR EACH ROW EXECUTE FUNCTION audit.log_table_change();

-- Users audit
DROP TRIGGER IF EXISTS audit_users ON auth.users;
CREATE TRIGGER audit_users
    AFTER INSERT OR UPDATE OR DELETE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION audit.log_table_change();

-- ============================================================================
-- Retention cleanup function
-- ============================================================================

CREATE OR REPLACE FUNCTION audit.cleanup_old_logs()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    rows_deleted INTEGER;
BEGIN
    -- Cleanup audit_logs based on retention_days
    DELETE FROM audit.audit_logs
    WHERE created_at < CURRENT_TIMESTAMP - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    deleted_count := deleted_count + rows_deleted;

    -- Cleanup login_audit (default 365 days)
    DELETE FROM audit.login_audit
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '365 days';
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    deleted_count := deleted_count + rows_deleted;

    -- Cleanup api_audit (default 90 days)
    DELETE FROM audit.api_audit
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days';
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    deleted_count := deleted_count + rows_deleted;

    -- Cleanup data_access_audit (default 365 days)
    DELETE FROM audit.data_access_audit
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '365 days';
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    deleted_count := deleted_count + rows_deleted;

    -- Cleanup config_change_audit (default 2 years)
    DELETE FROM audit.config_change_audit
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '730 days';
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;
    deleted_count := deleted_count + rows_deleted;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Record migration
-- ============================================================================

INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000007', 'audit', md5('000007_audit'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE audit.audit_logs IS 'General audit log for all system events';
COMMENT ON TABLE audit.login_audit IS 'Authentication and login events';
COMMENT ON TABLE audit.api_audit IS 'API access logging';
COMMENT ON TABLE audit.data_access_audit IS 'Sensitive data access tracking';
COMMENT ON TABLE audit.config_change_audit IS 'Configuration change history';
COMMENT ON FUNCTION audit.log_table_change IS 'Trigger function for automatic audit logging';
COMMENT ON FUNCTION audit.cleanup_old_logs IS 'Cleanup function for old audit logs';

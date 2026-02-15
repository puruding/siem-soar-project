-- ============================================================================
-- SIEM-SOAR Platform: Detection Rules Migration
-- ============================================================================
-- Migration: 000004_rules
-- Purpose: Detection rules, Sigma support, and correlation rules
-- ============================================================================

-- ============================================================================
-- Rule Type Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE meta.rule_type AS ENUM (
        'SIGMA',
        'YARA',
        'CUSTOM',
        'CORRELATION',
        'IOC',
        'ML_ANOMALY',
        'THRESHOLD',
        'BEHAVIORAL'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Rule Status Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE meta.rule_status AS ENUM (
        'DRAFT',
        'TESTING',
        'ENABLED',
        'DISABLED',
        'DEPRECATED',
        'ARCHIVED'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Detection Rules Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    rule_id VARCHAR(100) NOT NULL,  -- Human-readable ID (e.g., SIEM-001)
    name VARCHAR(255) NOT NULL,
    title VARCHAR(255),
    description TEXT,

    -- Classification
    rule_type meta.rule_type NOT NULL,
    severity severity_level DEFAULT 'MEDIUM',
    confidence FLOAT DEFAULT 0.7,

    -- Rule Content
    rule_content TEXT NOT NULL,  -- Sigma YAML, YARA rule, SQL query, etc.
    rule_format VARCHAR(20),  -- yaml, json, sql, etc.
    compiled_query TEXT,  -- Pre-compiled ClickHouse SQL

    -- MITRE ATT&CK Mapping
    mitre_tactics TEXT[],
    mitre_techniques TEXT[],
    mitre_sub_techniques TEXT[],

    -- Data Sources
    log_sources TEXT[],  -- Required log types
    platforms TEXT[],  -- windows, linux, macos, aws, etc.

    -- Alert Configuration
    alert_name VARCHAR(255),
    alert_description_template TEXT,
    alert_grouping JSONB DEFAULT '{
        "fields": ["principal_hostname", "principal_user_id"],
        "window_minutes": 5
    }'::JSONB,

    -- Threshold & Window
    threshold INTEGER DEFAULT 1,
    time_window_minutes INTEGER DEFAULT 5,
    count_distinct_field VARCHAR(100),

    -- False Positive Handling
    false_positives TEXT[],  -- Known FP patterns
    fp_rate FLOAT DEFAULT 0,  -- Calculated FP rate
    tuning_suggestions TEXT,

    -- Dependencies
    depends_on UUID[],  -- Other rules this depends on
    child_rules UUID[],  -- Rules that depend on this

    -- Status & Lifecycle
    status meta.rule_status DEFAULT 'DRAFT',
    is_enabled BOOLEAN DEFAULT FALSE,
    is_system BOOLEAN DEFAULT FALSE,  -- Pre-built rules
    is_custom BOOLEAN DEFAULT TRUE,

    -- Execution Statistics
    executions_total BIGINT DEFAULT 0,
    matches_total BIGINT DEFAULT 0,
    alerts_total BIGINT DEFAULT 0,
    last_executed_at TIMESTAMPTZ,
    last_matched_at TIMESTAMPTZ,
    avg_execution_ms FLOAT,

    -- Quality Metrics
    true_positives BIGINT DEFAULT 0,
    false_positives_count BIGINT DEFAULT 0,
    precision_rate FLOAT,
    last_tuned_at TIMESTAMPTZ,

    -- Versioning
    version INTEGER DEFAULT 1,
    previous_version_id UUID,
    change_log TEXT,

    -- Source & Attribution
    author VARCHAR(255),
    "references" TEXT[],  -- URLs, CVE IDs, etc.
    license VARCHAR(100),
    source VARCHAR(100),  -- sigmahq, custom, vendor, etc.

    -- Tags
    tags TEXT[],
    labels JSONB DEFAULT '{}'::JSONB,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,
    approved_at TIMESTAMPTZ,
    approved_by UUID,

    CONSTRAINT detection_rules_id_tenant_unique UNIQUE (tenant_id, rule_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant ON meta.detection_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_rule_type ON meta.detection_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_detection_rules_status ON meta.detection_rules(status);
CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON meta.detection_rules(severity);
CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON meta.detection_rules(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre_tactics ON meta.detection_rules USING GIN (mitre_tactics);
CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre_techniques ON meta.detection_rules USING GIN (mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_detection_rules_tags ON meta.detection_rules USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_detection_rules_platforms ON meta.detection_rules USING GIN (platforms);

-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_detection_rules_search ON meta.detection_rules
    USING GIN (to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, '')));

-- Trigger for updated_at
CREATE TRIGGER update_detection_rules_updated_at
    BEFORE UPDATE ON meta.detection_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Rule Versions (History)
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.detection_rule_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID NOT NULL REFERENCES meta.detection_rules(id) ON DELETE CASCADE,

    -- Version info
    version INTEGER NOT NULL,
    rule_content TEXT NOT NULL,
    compiled_query TEXT,
    change_log TEXT,

    -- Snapshot of key fields
    severity severity_level,
    threshold INTEGER,
    time_window_minutes INTEGER,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT rule_versions_unique UNIQUE (rule_id, version)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_rule_versions_rule_id ON meta.detection_rule_versions(rule_id);

-- ============================================================================
-- Rule Exclusions (Tuning)
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.rule_exclusions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID NOT NULL REFERENCES meta.detection_rules(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Exclusion definition
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Field-based exclusion
    field_name VARCHAR(100) NOT NULL,
    operator VARCHAR(20) NOT NULL,  -- equals, contains, regex, in, not_in, starts_with, ends_with
    value TEXT NOT NULL,
    values TEXT[],  -- For 'in' operator

    -- Scope
    applies_to VARCHAR(50) DEFAULT 'all',  -- all, specific_assets, specific_users
    asset_ids UUID[],
    user_ids UUID[],

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    status entity_status DEFAULT 'ACTIVE',

    -- Expiration
    expires_at TIMESTAMPTZ,
    is_temporary BOOLEAN DEFAULT FALSE,

    -- Statistics
    matches_prevented BIGINT DEFAULT 0,
    last_match_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    reason TEXT,
    ticket_id VARCHAR(100)  -- Reference to ticketing system
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_rule_exclusions_rule ON meta.rule_exclusions(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_exclusions_tenant ON meta.rule_exclusions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rule_exclusions_enabled ON meta.rule_exclusions(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_rule_exclusions_expires ON meta.rule_exclusions(expires_at) WHERE expires_at IS NOT NULL;

-- Trigger for updated_at
CREATE TRIGGER update_rule_exclusions_updated_at
    BEFORE UPDATE ON meta.rule_exclusions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Correlation Rules (Complex Multi-Event Detection)
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.correlation_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID NOT NULL REFERENCES meta.detection_rules(id) ON DELETE CASCADE,

    -- Correlation Definition
    correlation_type VARCHAR(50) NOT NULL,  -- sequence, aggregation, pattern, join
    correlation_config JSONB NOT NULL,

    -- Sequence correlation (event A then B then C)
    sequence_steps JSONB,  -- Array of step definitions
    sequence_timeout_minutes INTEGER DEFAULT 30,
    sequence_ordered BOOLEAN DEFAULT TRUE,

    -- Aggregation correlation (count, sum, etc.)
    aggregation_function VARCHAR(20),  -- count, count_distinct, sum, avg
    aggregation_field VARCHAR(100),
    aggregation_threshold INTEGER,
    aggregation_window_minutes INTEGER,
    group_by_fields TEXT[],

    -- Pattern correlation (regex on event sequence)
    pattern_definition TEXT,

    -- Join correlation (events from different sources)
    join_conditions JSONB,
    join_window_minutes INTEGER,

    -- Output
    creates_alert BOOLEAN DEFAULT TRUE,
    triggers_playbook BOOLEAN DEFAULT FALSE,
    playbook_id UUID,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Index
CREATE INDEX IF NOT EXISTS idx_correlation_rules_rule ON meta.correlation_rules(rule_id);

-- ============================================================================
-- Rule Sets (Grouping Rules)
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.rule_sets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Classification
    category VARCHAR(100),  -- malware, lateral_movement, data_exfil, etc.
    subcategory VARCHAR(100),

    -- MITRE ATT&CK Coverage
    mitre_tactics_coverage TEXT[],
    mitre_techniques_coverage TEXT[],

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    status entity_status DEFAULT 'ACTIVE',

    -- Settings
    settings JSONB DEFAULT '{}'::JSONB,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT rule_sets_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_rule_sets_tenant ON meta.rule_sets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rule_sets_category ON meta.rule_sets(category);

-- Rule Set Membership
CREATE TABLE IF NOT EXISTS meta.rule_set_memberships (
    rule_set_id UUID NOT NULL REFERENCES meta.rule_sets(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL REFERENCES meta.detection_rules(id) ON DELETE CASCADE,

    -- Order within set
    sort_order INTEGER DEFAULT 0,

    -- Override settings
    override_severity severity_level,
    override_enabled BOOLEAN,

    -- Audit
    added_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    added_by UUID,

    PRIMARY KEY (rule_set_id, rule_id)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_rule_set_memberships_rule ON meta.rule_set_memberships(rule_id);

-- ============================================================================
-- IOC Lists (Indicators of Compromise)
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.ioc_lists (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Classification
    ioc_type VARCHAR(50) NOT NULL,  -- ip, domain, hash_md5, hash_sha256, url, email, etc.
    threat_type VARCHAR(100),  -- malware, phishing, c2, etc.
    confidence FLOAT DEFAULT 0.7,
    severity severity_level DEFAULT 'MEDIUM',

    -- Source
    source VARCHAR(100),  -- misp, threatfox, custom, etc.
    source_url VARCHAR(500),
    source_ref VARCHAR(255),

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    status entity_status DEFAULT 'ACTIVE',

    -- Statistics
    ioc_count INTEGER DEFAULT 0,
    match_count BIGINT DEFAULT 0,
    last_match_at TIMESTAMPTZ,

    -- TTL & Refresh
    ttl_days INTEGER DEFAULT 90,
    auto_refresh BOOLEAN DEFAULT FALSE,
    refresh_url VARCHAR(500),
    last_refreshed_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT ioc_lists_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Index
CREATE INDEX IF NOT EXISTS idx_ioc_lists_tenant ON meta.ioc_lists(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ioc_lists_ioc_type ON meta.ioc_lists(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_lists_enabled ON meta.ioc_lists(is_enabled) WHERE is_enabled = TRUE;

-- IOC Entries
CREATE TABLE IF NOT EXISTS meta.ioc_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    list_id UUID NOT NULL REFERENCES meta.ioc_lists(id) ON DELETE CASCADE,

    -- IOC Value
    value TEXT NOT NULL,
    value_hash VARCHAR(64) NOT NULL,  -- For fast lookup

    -- Metadata
    description TEXT,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    actor VARCHAR(100),
    campaign VARCHAR(100),

    -- Confidence & Severity
    confidence FLOAT,
    severity severity_level,

    -- References
    "references" TEXT[],
    tags TEXT[],

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,

    -- Statistics
    match_count BIGINT DEFAULT 0,
    last_match_at TIMESTAMPTZ,
    first_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ioc_entries_value_list_unique UNIQUE (list_id, value_hash)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ioc_entries_list ON meta.ioc_entries(list_id);
CREATE INDEX IF NOT EXISTS idx_ioc_entries_hash ON meta.ioc_entries(value_hash);
CREATE INDEX IF NOT EXISTS idx_ioc_entries_enabled ON meta.ioc_entries(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_ioc_entries_expires ON meta.ioc_entries(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ioc_entries_value ON meta.ioc_entries(value);

-- Trigger for updated_at
CREATE TRIGGER update_ioc_entries_updated_at
    BEFORE UPDATE ON meta.ioc_entries
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Record migration
-- ============================================================================

INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000004', 'rules', md5('000004_rules'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE meta.detection_rules IS 'Detection rules including Sigma, YARA, and custom rules';
COMMENT ON TABLE meta.detection_rule_versions IS 'Version history for detection rules';
COMMENT ON TABLE meta.rule_exclusions IS 'Rule tuning exclusions to reduce false positives';
COMMENT ON TABLE meta.correlation_rules IS 'Complex multi-event correlation definitions';
COMMENT ON TABLE meta.rule_sets IS 'Logical grouping of related rules';
COMMENT ON TABLE meta.ioc_lists IS 'Indicator of Compromise lists';
COMMENT ON TABLE meta.ioc_entries IS 'Individual IOC entries';

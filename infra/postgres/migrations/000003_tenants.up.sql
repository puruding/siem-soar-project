-- ============================================================================
-- SIEM-SOAR Platform: Tenants & Organizations Migration
-- ============================================================================
-- Migration: 000003_tenants
-- Purpose: Multi-tenant support with organizations and billing
-- ============================================================================

-- ============================================================================
-- Tenant Tier Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE meta.tenant_tier AS ENUM (
        'FREE',
        'STARTER',
        'PROFESSIONAL',
        'ENTERPRISE',
        'CUSTOM'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Deployment Type Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE meta.deployment_type AS ENUM (
        'SAAS',
        'HYBRID',
        'ON_PREMISE'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Tenants Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,  -- URL-friendly identifier
    display_name VARCHAR(255),
    description TEXT,

    -- Contact
    primary_email VARCHAR(255) NOT NULL,
    billing_email VARCHAR(255),
    technical_email VARCHAR(255),
    phone VARCHAR(50),

    -- Address
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100),

    -- Subscription
    tier meta.tenant_tier DEFAULT 'STARTER',
    deployment meta.deployment_type DEFAULT 'SAAS',
    subscription_start_date DATE,
    subscription_end_date DATE,
    trial_ends_at TIMESTAMPTZ,
    is_trial BOOLEAN DEFAULT FALSE,

    -- Limits (per tier, can be overridden)
    max_users INTEGER DEFAULT 10,
    max_events_per_day BIGINT DEFAULT 1000000,
    max_storage_gb INTEGER DEFAULT 100,
    max_rules INTEGER DEFAULT 100,
    max_playbooks INTEGER DEFAULT 50,
    retention_days INTEGER DEFAULT 90,

    -- Features
    features JSONB DEFAULT '{
        "ai_triage": true,
        "auto_remediation": false,
        "nlp_search": true,
        "custom_rules": true,
        "api_access": true,
        "sso": false,
        "multi_siem": false,
        "agentic_ai": false
    }'::JSONB,

    -- Settings
    settings JSONB DEFAULT '{
        "timezone": "UTC",
        "date_format": "YYYY-MM-DD",
        "time_format": "HH:mm:ss",
        "theme": "light",
        "notification_preferences": {}
    }'::JSONB,

    -- Branding
    logo_url VARCHAR(500),
    favicon_url VARCHAR(500),
    primary_color VARCHAR(7) DEFAULT '#3B82F6',
    custom_domain VARCHAR(255),

    -- Integration keys (encrypted)
    clickhouse_database VARCHAR(100),
    kafka_topic_prefix VARCHAR(100),

    -- Status
    status entity_status DEFAULT 'ACTIVE',
    is_suspended BOOLEAN DEFAULT FALSE,
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT,
    deleted_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON meta.tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON meta.tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_tier ON meta.tenants(tier);
CREATE INDEX IF NOT EXISTS idx_tenants_deployment ON meta.tenants(deployment);

-- Trigger for updated_at
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON meta.tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Tenant Usage Statistics (Daily)
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.tenant_usage (
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,

    -- Volume metrics
    events_ingested BIGINT DEFAULT 0,
    bytes_ingested BIGINT DEFAULT 0,
    storage_used_bytes BIGINT DEFAULT 0,

    -- User metrics
    active_users INTEGER DEFAULT 0,
    api_calls BIGINT DEFAULT 0,

    -- Detection metrics
    rules_triggered INTEGER DEFAULT 0,
    alerts_generated INTEGER DEFAULT 0,

    -- SOAR metrics
    playbook_executions INTEGER DEFAULT 0,

    -- AI metrics
    ai_inferences BIGINT DEFAULT 0,
    ai_tokens_used BIGINT DEFAULT 0,

    PRIMARY KEY (tenant_id, date)
);

-- Index for date-range queries
CREATE INDEX IF NOT EXISTS idx_tenant_usage_date ON meta.tenant_usage(date);

-- ============================================================================
-- Tenant Invitations
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.tenant_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Invitation details
    email VARCHAR(255) NOT NULL,
    role auth.user_role NOT NULL DEFAULT 'SOC_ANALYST_L1',
    groups UUID[],  -- Array of group IDs to add user to

    -- Token
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',  -- PENDING, ACCEPTED, EXPIRED, REVOKED
    accepted_at TIMESTAMPTZ,
    accepted_by UUID,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    message TEXT,  -- Optional personal message

    CONSTRAINT tenant_invitations_email_unique UNIQUE (tenant_id, email, status)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_token ON meta.tenant_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_email ON meta.tenant_invitations(email);
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_status ON meta.tenant_invitations(status) WHERE status = 'PENDING';

-- ============================================================================
-- Data Sources Configuration
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.data_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Source configuration
    source_type VARCHAR(50) NOT NULL,  -- syslog, api, file, kafka, etc.
    vendor VARCHAR(100),
    product VARCHAR(100),
    version VARCHAR(50),

    -- Connection
    config JSONB NOT NULL,  -- Connection details (encrypted sensitive fields)

    -- Parser configuration
    parser_type VARCHAR(50) DEFAULT 'auto',  -- auto, json, cef, leef, grok, regex
    parser_config JSONB DEFAULT '{}'::JSONB,

    -- Normalization
    field_mapping JSONB DEFAULT '{}'::JSONB,

    -- Enrichment
    enrichment_enabled BOOLEAN DEFAULT TRUE,
    enrichment_config JSONB DEFAULT '{}'::JSONB,

    -- Filtering
    filter_rules JSONB DEFAULT '[]'::JSONB,
    sampling_rate FLOAT DEFAULT 1.0,

    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    status entity_status DEFAULT 'ACTIVE',
    health_status VARCHAR(20) DEFAULT 'UNKNOWN',  -- HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
    last_event_at TIMESTAMPTZ,
    last_error TEXT,
    error_count INTEGER DEFAULT 0,

    -- Statistics
    events_total BIGINT DEFAULT 0,
    events_today BIGINT DEFAULT 0,
    bytes_total BIGINT DEFAULT 0,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT data_sources_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant_id ON meta.data_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_data_sources_source_type ON meta.data_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_data_sources_health ON meta.data_sources(health_status);
CREATE INDEX IF NOT EXISTS idx_data_sources_enabled ON meta.data_sources(is_enabled) WHERE is_enabled = TRUE;

-- Trigger for updated_at
CREATE TRIGGER update_data_sources_updated_at
    BEFORE UPDATE ON meta.data_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Assets Inventory
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES meta.tenants(id) ON DELETE CASCADE,

    -- Identity
    asset_id VARCHAR(255) NOT NULL,  -- External/internal ID
    hostname VARCHAR(255),
    display_name VARCHAR(255),
    description TEXT,

    -- Type & Classification
    asset_type VARCHAR(50) NOT NULL,  -- server, workstation, network_device, cloud_resource, etc.
    os_family VARCHAR(50),
    os_name VARCHAR(100),
    os_version VARCHAR(50),

    -- Network
    ip_addresses INET[],
    mac_addresses MACADDR[],
    fqdn VARCHAR(255),

    -- Location
    location VARCHAR(255),
    data_center VARCHAR(100),
    zone VARCHAR(100),

    -- Cloud (if applicable)
    cloud_provider VARCHAR(50),
    cloud_account VARCHAR(100),
    cloud_region VARCHAR(50),
    cloud_resource_id VARCHAR(255),
    cloud_tags JSONB DEFAULT '{}'::JSONB,

    -- Ownership
    owner VARCHAR(255),
    department VARCHAR(100),
    business_unit VARCHAR(100),
    cost_center VARCHAR(50),

    -- Classification
    criticality severity_level DEFAULT 'MEDIUM',
    data_classification VARCHAR(50),  -- public, internal, confidential, restricted
    compliance_tags TEXT[],  -- PCI, HIPAA, SOX, etc.

    -- Agent
    agent_installed BOOLEAN DEFAULT FALSE,
    agent_version VARCHAR(50),
    agent_last_seen TIMESTAMPTZ,

    -- Status
    status entity_status DEFAULT 'ACTIVE',
    is_managed BOOLEAN DEFAULT TRUE,
    first_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    custom_fields JSONB DEFAULT '{}'::JSONB,
    tags TEXT[],

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT assets_id_tenant_unique UNIQUE (tenant_id, asset_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON meta.assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON meta.assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON meta.assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON meta.assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON meta.assets USING GIN (ip_addresses);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON meta.assets USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_assets_status ON meta.assets(status);

-- Trigger for updated_at
CREATE TRIGGER update_assets_updated_at
    BEFORE UPDATE ON meta.assets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Add tenant_id foreign key to users table
-- ============================================================================

ALTER TABLE auth.users
    ADD CONSTRAINT fk_users_tenant
    FOREIGN KEY (tenant_id) REFERENCES meta.tenants(id) ON DELETE CASCADE;

ALTER TABLE auth.api_keys
    ADD CONSTRAINT fk_api_keys_tenant
    FOREIGN KEY (tenant_id) REFERENCES meta.tenants(id) ON DELETE CASCADE;

ALTER TABLE auth.sessions
    ADD CONSTRAINT fk_sessions_tenant
    FOREIGN KEY (tenant_id) REFERENCES meta.tenants(id) ON DELETE CASCADE;

ALTER TABLE auth.user_groups
    ADD CONSTRAINT fk_user_groups_tenant
    FOREIGN KEY (tenant_id) REFERENCES meta.tenants(id) ON DELETE CASCADE;

ALTER TABLE auth.sso_providers
    ADD CONSTRAINT fk_sso_providers_tenant
    FOREIGN KEY (tenant_id) REFERENCES meta.tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- Record migration
-- ============================================================================

INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000003', 'tenants', md5('000003_tenants'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE meta.tenants IS 'Multi-tenant organizations';
COMMENT ON TABLE meta.tenant_usage IS 'Daily usage statistics per tenant';
COMMENT ON TABLE meta.tenant_invitations IS 'Pending user invitations';
COMMENT ON TABLE meta.data_sources IS 'Log source configurations';
COMMENT ON TABLE meta.assets IS 'Asset inventory for context enrichment';

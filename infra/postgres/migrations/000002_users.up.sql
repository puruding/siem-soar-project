-- ============================================================================
-- SIEM-SOAR Platform: Users & Authentication Migration
-- ============================================================================
-- Migration: 000002_users
-- Purpose: Create user authentication and authorization tables
-- ============================================================================

-- ============================================================================
-- User Role Enum
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE auth.user_role AS ENUM (
        'SUPER_ADMIN',      -- Platform administrator
        'TENANT_ADMIN',     -- Tenant administrator
        'SOC_MANAGER',      -- SOC team lead
        'SOC_ANALYST_L3',   -- Senior analyst
        'SOC_ANALYST_L2',   -- Mid-level analyst
        'SOC_ANALYST_L1',   -- Junior analyst
        'THREAT_HUNTER',    -- Threat hunting specialist
        'INCIDENT_RESPONDER', -- Incident response specialist
        'READONLY',         -- Read-only access
        'API_SERVICE'       -- Service account for API access
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Users Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,

    -- Identity
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),

    -- Authentication
    password_hash VARCHAR(255),  -- bcrypt hash, NULL for SSO-only users
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),     -- TOTP secret (encrypted)
    mfa_backup_codes TEXT[],     -- Encrypted backup codes

    -- Role & Permissions
    role auth.user_role NOT NULL DEFAULT 'SOC_ANALYST_L1',
    permissions JSONB DEFAULT '[]'::JSONB,  -- Additional granular permissions

    -- Profile
    avatar_url VARCHAR(500),
    timezone VARCHAR(50) DEFAULT 'UTC',
    locale VARCHAR(10) DEFAULT 'en',
    preferences JSONB DEFAULT '{}'::JSONB,

    -- Status
    status entity_status DEFAULT 'ACTIVE',
    is_system_user BOOLEAN DEFAULT FALSE,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMPTZ,

    -- Security
    password_changed_at TIMESTAMPTZ,
    must_change_password BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    -- Constraints
    CONSTRAINT users_email_unique UNIQUE (email),
    CONSTRAINT users_username_tenant_unique UNIQUE (tenant_id, username)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON auth.users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON auth.users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON auth.users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON auth.users(role);

-- Trigger for updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- API Keys Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,

    -- Key details
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,  -- First 8 chars for identification
    key_hash VARCHAR(255) NOT NULL,  -- SHA-256 hash of the full key
    description TEXT,

    -- Scope & Permissions
    scopes TEXT[] DEFAULT ARRAY['read']::TEXT[],
    permissions JSONB DEFAULT '[]'::JSONB,
    ip_whitelist INET[],

    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 100,
    rate_limit_per_day INTEGER DEFAULT 10000,

    -- Status & Expiry
    status entity_status DEFAULT 'ACTIVE',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,
    usage_count BIGINT DEFAULT 0,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,

    CONSTRAINT api_keys_prefix_unique UNIQUE (key_prefix)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON auth.api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON auth.api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON auth.api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON auth.api_keys(status);

-- Trigger for updated_at
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON auth.api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Sessions Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,

    -- Session details
    token_hash VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255),

    -- Device & Location
    user_agent TEXT,
    ip_address INET,
    device_type VARCHAR(50),
    device_name VARCHAR(255),
    location_country VARCHAR(100),
    location_city VARCHAR(100),

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(255)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON auth.sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON auth.sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON auth.sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON auth.sessions(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- User Groups Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.user_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Permissions inherited by all members
    role auth.user_role,
    permissions JSONB DEFAULT '[]'::JSONB,

    -- Settings
    is_default BOOLEAN DEFAULT FALSE,  -- Auto-assign new users
    is_system BOOLEAN DEFAULT FALSE,   -- Cannot be deleted

    -- Audit
    status entity_status DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT user_groups_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_groups_tenant_id ON auth.user_groups(tenant_id);

-- Trigger for updated_at
CREATE TRIGGER update_user_groups_updated_at
    BEFORE UPDATE ON auth.user_groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- User Group Memberships Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.user_group_memberships (
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES auth.user_groups(id) ON DELETE CASCADE,

    -- Membership details
    is_admin BOOLEAN DEFAULT FALSE,  -- Can manage group members
    joined_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    added_by UUID,

    PRIMARY KEY (user_id, group_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_group_memberships_group_id ON auth.user_group_memberships(group_id);

-- ============================================================================
-- Password Reset Tokens Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,

    -- Request metadata
    requested_from_ip INET,
    user_agent TEXT,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Index for token lookup
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON auth.password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires ON auth.password_reset_tokens(expires_at) WHERE used_at IS NULL;

-- ============================================================================
-- SSO Providers Configuration
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.sso_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,

    -- Provider details
    name VARCHAR(100) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,  -- 'saml', 'oidc', 'ldap'
    display_name VARCHAR(255),
    description TEXT,

    -- Configuration
    config JSONB NOT NULL,  -- Provider-specific config (encrypted fields)
    metadata_url VARCHAR(500),
    entity_id VARCHAR(255),

    -- Attribute mapping
    attribute_mapping JSONB DEFAULT '{
        "email": "email",
        "name": "displayName",
        "groups": "groups"
    }'::JSONB,

    -- Settings
    is_enabled BOOLEAN DEFAULT TRUE,
    is_default BOOLEAN DEFAULT FALSE,
    auto_provision BOOLEAN DEFAULT TRUE,
    default_role auth.user_role DEFAULT 'SOC_ANALYST_L1',

    -- Audit
    status entity_status DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT sso_providers_name_tenant_unique UNIQUE (tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sso_providers_tenant_id ON auth.sso_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sso_providers_enabled ON auth.sso_providers(is_enabled) WHERE is_enabled = TRUE;

-- Trigger for updated_at
CREATE TRIGGER update_sso_providers_updated_at
    BEFORE UPDATE ON auth.sso_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- User SSO Links Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS auth.user_sso_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES auth.sso_providers(id) ON DELETE CASCADE,

    -- External identity
    external_id VARCHAR(255) NOT NULL,
    external_email VARCHAR(255),
    external_username VARCHAR(255),

    -- Metadata
    provider_data JSONB DEFAULT '{}'::JSONB,

    -- Status
    is_primary BOOLEAN DEFAULT FALSE,
    linked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ,

    CONSTRAINT user_sso_links_unique UNIQUE (provider_id, external_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_sso_links_user_id ON auth.user_sso_links(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sso_links_external_id ON auth.user_sso_links(external_id);

-- ============================================================================
-- Record migration
-- ============================================================================

INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000002', 'users', md5('000002_users'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE auth.users IS 'User accounts for authentication and authorization';
COMMENT ON TABLE auth.api_keys IS 'API keys for programmatic access';
COMMENT ON TABLE auth.sessions IS 'Active user sessions';
COMMENT ON TABLE auth.user_groups IS 'Groups for organizing users and permissions';
COMMENT ON TABLE auth.user_group_memberships IS 'User to group membership mapping';
COMMENT ON TABLE auth.password_reset_tokens IS 'Password reset tokens';
COMMENT ON TABLE auth.sso_providers IS 'SSO provider configurations (SAML, OIDC, LDAP)';
COMMENT ON TABLE auth.user_sso_links IS 'Links between users and external SSO identities';

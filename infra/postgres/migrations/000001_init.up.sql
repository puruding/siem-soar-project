-- ============================================================================
-- SIEM-SOAR Platform: PostgreSQL Initial Migration
-- ============================================================================
-- Migration: 000001_init
-- Purpose: Create initial database structure, extensions, and schemas
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "btree_gist";

-- Create schemas for logical separation
CREATE SCHEMA IF NOT EXISTS auth;      -- Authentication & authorization
CREATE SCHEMA IF NOT EXISTS meta;      -- Metadata & configuration
CREATE SCHEMA IF NOT EXISTS soar;      -- SOAR-specific tables
CREATE SCHEMA IF NOT EXISTS audit;     -- Audit logging

-- Grant usage on schemas
GRANT USAGE ON SCHEMA auth TO PUBLIC;
GRANT USAGE ON SCHEMA meta TO PUBLIC;
GRANT USAGE ON SCHEMA soar TO PUBLIC;
GRANT USAGE ON SCHEMA audit TO PUBLIC;

-- ============================================================================
-- Common Types
-- ============================================================================

-- Severity level enum
DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM (
        'UNKNOWN',
        'INFORMATIONAL',
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Status enum for various entities
DO $$ BEGIN
    CREATE TYPE entity_status AS ENUM (
        'ACTIVE',
        'INACTIVE',
        'DELETED',
        'PENDING',
        'ARCHIVED'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- Base functions
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Function to set created_at if not provided
CREATE OR REPLACE FUNCTION set_created_at_column()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.created_at IS NULL THEN
        NEW.created_at = CURRENT_TIMESTAMP;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Function to generate short IDs (for human-readable identifiers)
CREATE OR REPLACE FUNCTION generate_short_id(prefix TEXT DEFAULT '')
RETURNS TEXT AS $$
DECLARE
    chars TEXT := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    result TEXT := '';
    i INT;
BEGIN
    FOR i IN 1..8 LOOP
        result := result || substr(chars, floor(random() * length(chars) + 1)::INT, 1);
    END LOOP;
    IF prefix != '' THEN
        RETURN prefix || '-' || result;
    END IF;
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Configuration table for system settings
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.system_config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    is_secret BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_system_config_updated_at
    BEFORE UPDATE ON meta.system_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default configurations
INSERT INTO meta.system_config (key, value, description) VALUES
    ('database_version', '"1"', 'Current database schema version'),
    ('default_retention_days', '90', 'Default data retention in days'),
    ('max_users_per_tenant', '1000', 'Maximum users allowed per tenant'),
    ('alert_sla_minutes', '{"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}', 'SLA targets by severity in minutes'),
    ('feature_flags', '{"ai_triage": true, "auto_remediation": false, "nlp_search": true}', 'Feature flags')
ON CONFLICT (key) DO NOTHING;

-- ============================================================================
-- Migration tracking table
-- ============================================================================

CREATE TABLE IF NOT EXISTS meta.schema_migrations (
    version VARCHAR(14) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    checksum VARCHAR(64),
    execution_time_ms INTEGER
);

-- Record this migration
INSERT INTO meta.schema_migrations (version, name, checksum)
VALUES ('000001', 'init', md5('000001_init'))
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON SCHEMA auth IS 'Authentication and authorization related tables';
COMMENT ON SCHEMA meta IS 'Metadata and configuration tables';
COMMENT ON SCHEMA soar IS 'SOAR (Security Orchestration, Automation and Response) tables';
COMMENT ON SCHEMA audit IS 'Audit logging tables';

COMMENT ON TABLE meta.system_config IS 'System-wide configuration key-value store';
COMMENT ON TABLE meta.schema_migrations IS 'Database migration version tracking';

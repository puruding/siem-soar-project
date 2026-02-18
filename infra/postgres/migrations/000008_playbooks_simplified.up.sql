-- ============================================================================
-- SIEM-SOAR Platform: Simplified Playbooks Table for Dashboard Integration
-- ============================================================================
-- Migration: 000008_playbooks_simplified
-- Purpose: Simplified playbook storage for React Dashboard with TEXT ID support
-- Note: This migration creates a simplified version of the playbooks table
--       that supports the PB-{timestamp} ID format used by the frontend
-- ============================================================================

-- Drop existing playbooks table if switching to simplified schema
-- WARNING: This will delete existing playbook data
-- DROP TABLE IF EXISTS soar.playbooks CASCADE;

-- ============================================================================
-- Simplified Playbooks Table (Dashboard Integration)
-- ============================================================================
-- This table is designed for direct integration with the React Dashboard
-- Key differences from 000006_playbooks:
-- 1. Uses TEXT for ID (supports "PB-1771431484622" format)
-- 2. Simplified definition JSONB structure (nodes, edges, variables)
-- 3. Reduced columns for MVP functionality

CREATE TABLE IF NOT EXISTS soar.playbooks (
    -- Primary Key: TEXT type to support "PB-{timestamp}" format from frontend
    id TEXT PRIMARY KEY,

    -- Multi-tenant support
    tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',

    -- Basic metadata
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(100) DEFAULT 'custom',

    -- Version control
    version INTEGER DEFAULT 1,
    is_latest BOOLEAN DEFAULT TRUE,

    -- Playbook definition (ReactFlow nodes, edges, variables)
    -- Structure:
    -- {
    --   "nodes": [{"id": "...", "type": "trigger", "position": {...}, "data": {...}}],
    --   "edges": [{"id": "...", "source": "...", "target": "...", "type": "..."}],
    --   "variables": [{"id": "...", "name": "...", "type": "...", "scope": "...", "value": ...}]
    -- }
    definition JSONB NOT NULL DEFAULT '{}'::JSONB,

    -- Trigger configuration
    trigger_config JSONB DEFAULT '{}'::JSONB,
    trigger_type VARCHAR(50) DEFAULT 'manual',  -- manual, alert, schedule, webhook

    -- Status
    status VARCHAR(20) DEFAULT 'DRAFT',  -- DRAFT, TESTING, ACTIVE, DISABLED
    is_enabled BOOLEAN DEFAULT FALSE,

    -- Tags for filtering
    tags TEXT[] DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_tenant
    ON soar.playbooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_status
    ON soar.playbooks(status);
CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_category
    ON soar.playbooks(category);
CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_enabled
    ON soar.playbooks(is_enabled) WHERE is_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_trigger_type
    ON soar.playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_tags
    ON soar.playbooks USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_playbooks_simplified_created
    ON soar.playbooks(created_at DESC);

-- ============================================================================
-- Trigger for auto-updating updated_at
-- ============================================================================

-- Create trigger function if not exists
CREATE OR REPLACE FUNCTION update_playbooks_simplified_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger
DROP TRIGGER IF EXISTS trigger_playbooks_simplified_updated_at ON soar.playbooks;
CREATE TRIGGER trigger_playbooks_simplified_updated_at
    BEFORE UPDATE ON soar.playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_playbooks_simplified_updated_at();

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE soar.playbooks IS 'Simplified playbook storage for React Dashboard integration';
COMMENT ON COLUMN soar.playbooks.id IS 'TEXT ID in format PB-{timestamp} from frontend';
COMMENT ON COLUMN soar.playbooks.definition IS 'ReactFlow graph: {nodes, edges, variables}';
COMMENT ON COLUMN soar.playbooks.trigger_type IS 'manual, alert, schedule, webhook';
COMMENT ON COLUMN soar.playbooks.status IS 'DRAFT, TESTING, ACTIVE, DISABLED';

-- ============================================================================
-- Sample Data (Optional - for development/testing)
-- ============================================================================

-- INSERT INTO soar.playbooks (id, name, display_name, description, category, trigger_type, status, is_enabled, definition)
-- VALUES (
--     'PB-sample-001',
--     'Sample Playbook',
--     'Sample Playbook',
--     'A sample playbook for testing',
--     'custom',
--     'manual',
--     'DRAFT',
--     false,
--     '{
--         "nodes": [
--             {"id": "trigger-1", "type": "trigger", "position": {"x": 250, "y": 50}, "data": {"label": "Manual Trigger"}}
--         ],
--         "edges": [],
--         "variables": []
--     }'::JSONB
-- );

-- ============================================================================
-- SIEM-SOAR Platform: Playbook Rules for ML-Enriched Alert Processing
-- ============================================================================
-- Migration: 000009_playbook_rules
-- Purpose: Playbook mapping rules for automatic playbook triggering based on
--          alert conditions and ML analysis results
-- ============================================================================

-- ============================================================================
-- Playbook Rules Table
-- ============================================================================
-- This table defines rules for automatically triggering playbooks based on
-- alert characteristics and ML analysis results from the Detection service.

CREATE TABLE IF NOT EXISTS soar.playbook_rules (
    -- Primary Key
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Rule Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Linked Playbook
    playbook_id TEXT NOT NULL,  -- References soar.playbooks(id) - TEXT type for PB-{timestamp} format

    -- Priority (lower = higher priority)
    priority INTEGER DEFAULT 100,

    -- Status
    enabled BOOLEAN DEFAULT true,

    -- Human-in-the-loop approval
    require_approval BOOLEAN DEFAULT false,

    -- Alert Conditions (JSON array of conditions)
    -- Each condition: {"field": "alert.severity", "operator": "eq", "value": "critical"}
    -- Supported operators: eq, neq, gt, lt, gte, lte, in, not_in, contains, not_contains, exists, not_exists
    -- Supported fields: alert.id, alert.tenant_id, alert.rule_id, alert.rule_name, alert.severity,
    --                   alert.title, alert.description, matched_fields.*, attack.tactics, attack.techniques
    conditions JSONB NOT NULL DEFAULT '[]',

    -- ML-Specific Conditions (optional)
    -- Structure:
    -- {
    --   "min_risk_score": 0.7,        -- >= threshold
    --   "max_risk_score": null,       -- <= threshold
    --   "priorities": ["critical", "high"],
    --   "exclude_fp": true,           -- Skip if is_false_positive=true
    --   "min_fp_confidence": 0.8,     -- FP confidence threshold
    --   "required_tactics": ["initial-access", "execution"],
    --   "required_techniques": ["T1566", "T1059"]
    -- }
    ml_conditions JSONB,

    -- Multi-tenant support
    tenant_id TEXT,  -- NULL = applies to all tenants

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- Indexes
-- ============================================================================

-- Index for enabled rules (most common query)
CREATE INDEX IF NOT EXISTS idx_playbook_rules_enabled
    ON soar.playbook_rules(enabled)
    WHERE enabled = true;

-- Index for playbook reference
CREATE INDEX IF NOT EXISTS idx_playbook_rules_playbook
    ON soar.playbook_rules(playbook_id);

-- Index for tenant filtering
CREATE INDEX IF NOT EXISTS idx_playbook_rules_tenant
    ON soar.playbook_rules(tenant_id)
    WHERE tenant_id IS NOT NULL;

-- Index for priority sorting
CREATE INDEX IF NOT EXISTS idx_playbook_rules_priority
    ON soar.playbook_rules(priority);

-- GIN index for JSONB conditions searching
CREATE INDEX IF NOT EXISTS idx_playbook_rules_conditions
    ON soar.playbook_rules USING GIN (conditions);

-- GIN index for JSONB ML conditions searching
CREATE INDEX IF NOT EXISTS idx_playbook_rules_ml_conditions
    ON soar.playbook_rules USING GIN (ml_conditions)
    WHERE ml_conditions IS NOT NULL;

-- ============================================================================
-- Trigger for auto-updating updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION update_playbook_rules_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_playbook_rules_updated_at ON soar.playbook_rules;
CREATE TRIGGER trigger_playbook_rules_updated_at
    BEFORE UPDATE ON soar.playbook_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_playbook_rules_updated_at();

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE soar.playbook_rules IS
    'Defines rules for automatically triggering playbooks based on alert and ML conditions';

COMMENT ON COLUMN soar.playbook_rules.id IS
    'Unique identifier for the rule';

COMMENT ON COLUMN soar.playbook_rules.name IS
    'Human-readable name for the rule';

COMMENT ON COLUMN soar.playbook_rules.description IS
    'Detailed description of when this rule triggers';

COMMENT ON COLUMN soar.playbook_rules.playbook_id IS
    'ID of the playbook to execute when rule matches (PB-{timestamp} format)';

COMMENT ON COLUMN soar.playbook_rules.priority IS
    'Rule priority for ordering (lower = higher priority, evaluated first)';

COMMENT ON COLUMN soar.playbook_rules.enabled IS
    'Whether this rule is active and should be evaluated';

COMMENT ON COLUMN soar.playbook_rules.require_approval IS
    'If true, playbook execution requires human approval before proceeding';

COMMENT ON COLUMN soar.playbook_rules.conditions IS
    'JSON array of conditions that must all match for rule to trigger';

COMMENT ON COLUMN soar.playbook_rules.ml_conditions IS
    'ML-specific conditions based on AI triage analysis results';

COMMENT ON COLUMN soar.playbook_rules.tenant_id IS
    'Tenant scope (NULL = applies to all tenants)';

-- ============================================================================
-- Sample Data (for development/testing)
-- ============================================================================

-- Example: Critical severity alerts from specific rule
-- INSERT INTO soar.playbook_rules (name, description, playbook_id, priority, conditions, ml_conditions)
-- VALUES (
--     'Critical Alert Response',
--     'Automatically trigger incident response playbook for critical severity alerts',
--     'PB-critical-response',
--     10,
--     '[{"field": "alert.severity", "operator": "eq", "value": "critical"}]'::JSONB,
--     '{"min_risk_score": 0.8, "exclude_fp": true}'::JSONB
-- );

-- Example: High-risk ML-detected threats
-- INSERT INTO soar.playbook_rules (name, description, playbook_id, priority, conditions, ml_conditions)
-- VALUES (
--     'High Risk Threat Investigation',
--     'Trigger investigation playbook for high ML risk score threats',
--     'PB-investigation',
--     20,
--     '[]'::JSONB,
--     '{"min_risk_score": 0.7, "priorities": ["critical", "high"], "exclude_fp": true}'::JSONB
-- );

-- Example: MITRE ATT&CK Initial Access detection
-- INSERT INTO soar.playbook_rules (name, description, playbook_id, priority, require_approval, conditions, ml_conditions)
-- VALUES (
--     'Initial Access Response',
--     'Respond to initial access techniques with approval required',
--     'PB-containment',
--     30,
--     true,
--     '[]'::JSONB,
--     '{"required_tactics": ["initial-access"], "min_risk_score": 0.6, "exclude_fp": true}'::JSONB
-- );

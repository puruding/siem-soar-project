-- ============================================================================
-- SIEM-SOAR Platform: Playbook Rules Migration Rollback
-- ============================================================================
-- Migration: 000009_playbook_rules (down)
-- Purpose: Rollback playbook rules table
-- ============================================================================

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_playbook_rules_updated_at ON soar.playbook_rules;

-- Drop function
DROP FUNCTION IF EXISTS update_playbook_rules_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS soar.idx_playbook_rules_enabled;
DROP INDEX IF EXISTS soar.idx_playbook_rules_playbook;
DROP INDEX IF EXISTS soar.idx_playbook_rules_tenant;
DROP INDEX IF EXISTS soar.idx_playbook_rules_priority;
DROP INDEX IF EXISTS soar.idx_playbook_rules_conditions;
DROP INDEX IF EXISTS soar.idx_playbook_rules_ml_conditions;

-- Drop table
DROP TABLE IF EXISTS soar.playbook_rules;

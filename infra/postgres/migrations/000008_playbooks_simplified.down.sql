-- ============================================================================
-- SIEM-SOAR Platform: Rollback Simplified Playbooks Table
-- ============================================================================
-- Migration: 000008_playbooks_simplified (DOWN)
-- ============================================================================

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_playbooks_simplified_updated_at ON soar.playbooks;

-- Drop function
DROP FUNCTION IF EXISTS update_playbooks_simplified_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_tenant;
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_status;
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_category;
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_enabled;
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_trigger_type;
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_tags;
DROP INDEX IF EXISTS soar.idx_playbooks_simplified_created;

-- Drop table
DROP TABLE IF EXISTS soar.playbooks;

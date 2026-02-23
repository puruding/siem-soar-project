-- ============================================================================
-- SIEM-SOAR Platform: SOAR Executions Table Rollback
-- ============================================================================
-- Migration: 000010_soar_executions (DOWN)
-- Purpose: Remove SOAR executions table and related objects
-- ============================================================================

-- Drop trigger first
DROP TRIGGER IF EXISTS trg_soar_executions_updated ON soar.executions;

-- Drop trigger function
DROP FUNCTION IF EXISTS soar.update_execution_timestamp();

-- Drop indexes (CASCADE will handle these, but explicit for clarity)
DROP INDEX IF EXISTS soar.idx_soar_executions_tenant;
DROP INDEX IF EXISTS soar.idx_soar_executions_playbook;
DROP INDEX IF EXISTS soar.idx_soar_executions_alert;
DROP INDEX IF EXISTS soar.idx_soar_executions_case;
DROP INDEX IF EXISTS soar.idx_soar_executions_status;
DROP INDEX IF EXISTS soar.idx_soar_executions_workflow;
DROP INDEX IF EXISTS soar.idx_soar_executions_created;
DROP INDEX IF EXISTS soar.idx_soar_executions_tenant_status;

-- Drop table
DROP TABLE IF EXISTS soar.executions;

-- ============================================================================
-- SIEM-SOAR Platform: Users & Authentication Migration (Rollback)
-- ============================================================================
-- Migration: 000002_users (DOWN)
-- Purpose: Rollback user authentication and authorization tables
-- ============================================================================

-- Drop tables in reverse order of dependencies
DROP TABLE IF EXISTS auth.user_sso_links CASCADE;
DROP TABLE IF EXISTS auth.sso_providers CASCADE;
DROP TABLE IF EXISTS auth.password_reset_tokens CASCADE;
DROP TABLE IF EXISTS auth.user_group_memberships CASCADE;
DROP TABLE IF EXISTS auth.user_groups CASCADE;
DROP TABLE IF EXISTS auth.sessions CASCADE;
DROP TABLE IF EXISTS auth.api_keys CASCADE;
DROP TABLE IF EXISTS auth.users CASCADE;

-- Drop custom types
DROP TYPE IF EXISTS auth.user_role CASCADE;

-- Remove migration record
DELETE FROM meta.schema_migrations WHERE version = '000002';

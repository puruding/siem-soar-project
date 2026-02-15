-- ============================================================================
-- SIEM-SOAR Platform: PostgreSQL Initial Migration (Rollback)
-- ============================================================================
-- Migration: 000001_init (DOWN)
-- Purpose: Rollback initial database structure
-- ============================================================================

-- Drop tables in reverse order
DROP TABLE IF EXISTS meta.schema_migrations CASCADE;
DROP TABLE IF EXISTS meta.system_config CASCADE;

-- Drop functions
DROP FUNCTION IF EXISTS generate_short_id(TEXT);
DROP FUNCTION IF EXISTS set_created_at_column();
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop custom types
DROP TYPE IF EXISTS entity_status CASCADE;
DROP TYPE IF EXISTS severity_level CASCADE;

-- Drop schemas (will fail if not empty, which is expected)
DROP SCHEMA IF EXISTS audit CASCADE;
DROP SCHEMA IF EXISTS soar CASCADE;
DROP SCHEMA IF EXISTS meta CASCADE;
DROP SCHEMA IF EXISTS auth CASCADE;

-- Note: Extensions are NOT dropped as they may be used by other databases
-- DROP EXTENSION IF EXISTS "btree_gist";
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "uuid-ossp";

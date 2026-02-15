-- ClickHouse Initialization Script
-- SIEM-SOAR Platform
--
-- This script is executed on first container startup.
-- Creates databases and initial settings.

-- Create main SIEM database
CREATE DATABASE IF NOT EXISTS siem ON CLUSTER '{cluster}';

-- Create metrics database for time-series metrics
CREATE DATABASE IF NOT EXISTS siem_metrics ON CLUSTER '{cluster}';

-- Set default database
USE siem;

-- Grant permissions (execute as admin user)
-- GRANT SELECT, INSERT, ALTER, CREATE, DROP ON siem.* TO siem_app;
-- GRANT SELECT ON siem.* TO siem_readonly;
-- GRANT SELECT, INSERT, ALTER, CREATE, DROP ON siem_metrics.* TO siem_app;
-- GRANT SELECT ON siem_metrics.* TO siem_readonly;

-- Verify cluster is operational
SELECT
    cluster,
    shard_num,
    replica_num,
    host_name,
    is_local
FROM system.clusters
WHERE cluster = 'siem_cluster';

-- ============================================================================
-- SIEM-SOAR Platform: Materialized Views for Analytics
-- ============================================================================
-- Purpose: Pre-aggregated views for fast dashboard queries
-- Engine: ReplicatedSummingMergeTree / ReplicatedAggregatingMergeTree
-- TTL: Varies by granularity (longer for coarser aggregations)
-- ============================================================================

-- ============================================================================
-- 1. Events Hourly Statistics
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.events_hourly ON CLUSTER '{cluster}'
(
    tenant_id                       String,
    hour                            DateTime,
    event_type                      Enum16(
                                        'GENERIC_EVENT' = 0,
                                        'NETWORK_CONNECTION' = 100,
                                        'NETWORK_DNS' = 101,
                                        'NETWORK_DHCP' = 102,
                                        'NETWORK_HTTP' = 103,
                                        'NETWORK_FLOW' = 104,
                                        'NETWORK_EMAIL' = 110,
                                        'USER_LOGIN' = 200,
                                        'USER_LOGOUT' = 201,
                                        'USER_CREATION' = 202,
                                        'USER_CHANGE' = 203,
                                        'USER_DELETION' = 204,
                                        'USER_PRIVILEGE_CHANGE' = 205,
                                        'PROCESS_LAUNCH' = 300,
                                        'PROCESS_TERMINATION' = 301,
                                        'PROCESS_INJECTION' = 302,
                                        'FILE_CREATION' = 400,
                                        'FILE_MODIFICATION' = 401,
                                        'FILE_DELETION' = 402,
                                        'FILE_READ' = 403,
                                        'REGISTRY_CREATION' = 500,
                                        'REGISTRY_MODIFICATION' = 501,
                                        'REGISTRY_DELETION' = 502,
                                        'RESOURCE_ACCESS' = 600,
                                        'RESOURCE_PERMISSION_CHANGE' = 601,
                                        'SERVICE_START' = 700,
                                        'SERVICE_STOP' = 701,
                                        'SCHEDULED_TASK' = 702,
                                        'ALERT' = 800,
                                        'SCAN_NETWORK' = 900,
                                        'SCAN_VULNERABILITY' = 901
                                    ),
    vendor_name                     LowCardinality(String),
    product_name                    LowCardinality(String),
    security_severity               Enum8(
                                        'UNKNOWN' = 0,
                                        'INFORMATIONAL' = 1,
                                        'LOW' = 2,
                                        'MEDIUM' = 3,
                                        'HIGH' = 4,
                                        'CRITICAL' = 5
                                    ),

    -- Counts
    event_count                     UInt64,
    bytes_total                     UInt64,

    -- Unique counts (HyperLogLog approximation)
    unique_hosts_state              AggregateFunction(uniq, String),
    unique_users_state              AggregateFunction(uniq, String),
    unique_src_ips_state            AggregateFunction(uniq, IPv6),
    unique_dst_ips_state            AggregateFunction(uniq, IPv6),

    -- TI Statistics
    ti_matched_count                UInt64,

    -- Network Statistics
    network_bytes_sent              UInt64,
    network_bytes_received          UInt64
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/siem/events_hourly', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, event_type, vendor_name, product_name, security_severity)
TTL hour + INTERVAL 2 YEAR DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.events_hourly_mv ON CLUSTER '{cluster}'
TO siem.events_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    event_type,
    vendor_name,
    product_name,
    security_severity,
    count() AS event_count,
    sum(length(raw_log)) AS bytes_total,
    uniqState(principal_hostname) AS unique_hosts_state,
    uniqState(principal_user_id) AS unique_users_state,
    uniqState(arrayJoin(principal_ip)) AS unique_src_ips_state,
    uniqState(arrayJoin(target_ip)) AS unique_dst_ips_state,
    sum(ti_matched) AS ti_matched_count,
    sum(network_sent_bytes) AS network_bytes_sent,
    sum(network_received_bytes) AS network_bytes_received
FROM siem.events
GROUP BY tenant_id, hour, event_type, vendor_name, product_name, security_severity;

-- ============================================================================
-- 2. Events Daily Statistics
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.events_daily ON CLUSTER '{cluster}'
(
    tenant_id                       String,
    date                            Date,
    event_type                      Enum16(
                                        'GENERIC_EVENT' = 0,
                                        'NETWORK_CONNECTION' = 100,
                                        'NETWORK_DNS' = 101,
                                        'NETWORK_DHCP' = 102,
                                        'NETWORK_HTTP' = 103,
                                        'NETWORK_FLOW' = 104,
                                        'NETWORK_EMAIL' = 110,
                                        'USER_LOGIN' = 200,
                                        'USER_LOGOUT' = 201,
                                        'USER_CREATION' = 202,
                                        'USER_CHANGE' = 203,
                                        'USER_DELETION' = 204,
                                        'USER_PRIVILEGE_CHANGE' = 205,
                                        'PROCESS_LAUNCH' = 300,
                                        'PROCESS_TERMINATION' = 301,
                                        'PROCESS_INJECTION' = 302,
                                        'FILE_CREATION' = 400,
                                        'FILE_MODIFICATION' = 401,
                                        'FILE_DELETION' = 402,
                                        'FILE_READ' = 403,
                                        'REGISTRY_CREATION' = 500,
                                        'REGISTRY_MODIFICATION' = 501,
                                        'REGISTRY_DELETION' = 502,
                                        'RESOURCE_ACCESS' = 600,
                                        'RESOURCE_PERMISSION_CHANGE' = 601,
                                        'SERVICE_START' = 700,
                                        'SERVICE_STOP' = 701,
                                        'SCHEDULED_TASK' = 702,
                                        'ALERT' = 800,
                                        'SCAN_NETWORK' = 900,
                                        'SCAN_VULNERABILITY' = 901
                                    ),

    -- Counts
    event_count                     UInt64,
    bytes_total                     UInt64,

    -- Unique counts
    unique_hosts_state              AggregateFunction(uniq, String),
    unique_users_state              AggregateFunction(uniq, String),
    unique_src_ips_state            AggregateFunction(uniq, IPv6),
    unique_dst_ips_state            AggregateFunction(uniq, IPv6),

    -- TI Statistics
    ti_matched_count                UInt64
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/siem/events_daily', '{replica}')
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, date, event_type)
TTL date + INTERVAL 5 YEAR DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.events_daily_mv ON CLUSTER '{cluster}'
TO siem.events_daily
AS SELECT
    tenant_id,
    toDate(timestamp) AS date,
    event_type,
    count() AS event_count,
    sum(length(raw_log)) AS bytes_total,
    uniqState(principal_hostname) AS unique_hosts_state,
    uniqState(principal_user_id) AS unique_users_state,
    uniqState(arrayJoin(principal_ip)) AS unique_src_ips_state,
    uniqState(arrayJoin(target_ip)) AS unique_dst_ips_state,
    sum(ti_matched) AS ti_matched_count
FROM siem.events
GROUP BY tenant_id, date, event_type;

-- ============================================================================
-- 3. Top Talkers (IP Address Statistics)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.top_talkers_hourly ON CLUSTER '{cluster}'
(
    tenant_id                       String,
    hour                            DateTime,
    ip_address                      IPv6,
    ip_role                         Enum8('SOURCE' = 1, 'DESTINATION' = 2),

    -- Counts
    event_count                     UInt64,
    connection_count                UInt64,
    bytes_total                     UInt64,

    -- Protocol breakdown
    tcp_connections                 UInt64,
    udp_connections                 UInt64,

    -- Unique destinations/sources
    unique_peers_state              AggregateFunction(uniq, IPv6),
    unique_ports_state              AggregateFunction(uniq, UInt16),

    -- GeoIP (captured at insert)
    geo_country                     LowCardinality(String),
    geo_asn                         UInt32
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/siem/top_talkers_hourly', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, ip_role, ip_address)
TTL hour + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- Source IPs
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.top_talkers_src_mv ON CLUSTER '{cluster}'
TO siem.top_talkers_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    ip AS ip_address,
    CAST('SOURCE' AS Enum8('SOURCE' = 1, 'DESTINATION' = 2)) AS ip_role,
    count() AS event_count,
    countIf(event_type IN ('NETWORK_CONNECTION', 'NETWORK_FLOW')) AS connection_count,
    sum(network_sent_bytes + network_received_bytes) AS bytes_total,
    countIf(network_ip_protocol = 'TCP') AS tcp_connections,
    countIf(network_ip_protocol = 'UDP') AS udp_connections,
    uniqState(arrayJoin(target_ip)) AS unique_peers_state,
    uniqState(target_port) AS unique_ports_state,
    any(principal_geo_country) AS geo_country,
    any(principal_geo_asn) AS geo_asn
FROM siem.events
ARRAY JOIN principal_ip AS ip
WHERE length(principal_ip) > 0
GROUP BY tenant_id, hour, ip;

-- Destination IPs
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.top_talkers_dst_mv ON CLUSTER '{cluster}'
TO siem.top_talkers_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    ip AS ip_address,
    CAST('DESTINATION' AS Enum8('SOURCE' = 1, 'DESTINATION' = 2)) AS ip_role,
    count() AS event_count,
    countIf(event_type IN ('NETWORK_CONNECTION', 'NETWORK_FLOW')) AS connection_count,
    sum(network_sent_bytes + network_received_bytes) AS bytes_total,
    countIf(network_ip_protocol = 'TCP') AS tcp_connections,
    countIf(network_ip_protocol = 'UDP') AS udp_connections,
    uniqState(arrayJoin(principal_ip)) AS unique_peers_state,
    uniqState(principal_port) AS unique_ports_state,
    any(target_geo_country) AS geo_country,
    any(target_geo_asn) AS geo_asn
FROM siem.events
ARRAY JOIN target_ip AS ip
WHERE length(target_ip) > 0
GROUP BY tenant_id, hour, ip;

-- ============================================================================
-- 4. User Activity Statistics
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.user_activity_hourly ON CLUSTER '{cluster}'
(
    tenant_id                       String,
    hour                            DateTime,
    user_id                         String,
    domain                          String,

    -- Activity Counts
    event_count                     UInt64,
    login_count                     UInt64,
    failed_login_count              UInt64,
    privilege_change_count          UInt64,
    process_launch_count            UInt64,
    file_access_count               UInt64,

    -- Unique resources
    unique_hosts_state              AggregateFunction(uniq, String),
    unique_apps_state               AggregateFunction(uniq, String),

    -- Network activity
    unique_dst_ips_state            AggregateFunction(uniq, IPv6),
    bytes_sent                      UInt64,

    -- Security events
    alert_count                     UInt64,
    blocked_count                   UInt64
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/siem/user_activity_hourly', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, user_id)
TTL hour + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.user_activity_hourly_mv ON CLUSTER '{cluster}'
TO siem.user_activity_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    principal_user_id AS user_id,
    principal_domain AS domain,
    count() AS event_count,
    countIf(event_type = 'USER_LOGIN') AS login_count,
    countIf(event_type = 'USER_LOGIN' AND security_action = 'BLOCK') AS failed_login_count,
    countIf(event_type = 'USER_PRIVILEGE_CHANGE') AS privilege_change_count,
    countIf(event_type = 'PROCESS_LAUNCH') AS process_launch_count,
    countIf(event_type IN ('FILE_CREATION', 'FILE_MODIFICATION', 'FILE_READ')) AS file_access_count,
    uniqState(principal_hostname) AS unique_hosts_state,
    uniqState(target_application) AS unique_apps_state,
    uniqState(arrayJoin(target_ip)) AS unique_dst_ips_state,
    sum(network_sent_bytes) AS bytes_sent,
    countIf(event_type = 'ALERT') AS alert_count,
    countIf(security_action = 'BLOCK') AS blocked_count
FROM siem.events
WHERE principal_user_id != ''
GROUP BY tenant_id, hour, user_id, domain;

-- ============================================================================
-- 5. Detection Rule Performance
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.rule_performance_hourly ON CLUSTER '{cluster}'
(
    tenant_id                       String,
    hour                            DateTime,
    rule_id                         String,
    rule_name                       String,
    rule_type                       Enum8(
                                        'UNKNOWN' = 0,
                                        'SIGMA' = 1,
                                        'YARA' = 2,
                                        'CUSTOM' = 3,
                                        'ML' = 4,
                                        'CORRELATION' = 5,
                                        'IOC' = 6
                                    ),

    -- Detection counts
    match_count                     UInt64,
    alert_count                     UInt64,

    -- Resolution breakdown
    true_positive_count             UInt64,
    false_positive_count            UInt64,
    unresolved_count                UInt64,

    -- Affected entities
    unique_hosts_state              AggregateFunction(uniq, String),
    unique_users_state              AggregateFunction(uniq, String),

    -- MITRE mapping
    mitre_tactics                   Array(String),
    mitre_techniques                Array(String)
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/siem/rule_performance_hourly', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, rule_id)
TTL hour + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.rule_performance_hourly_mv ON CLUSTER '{cluster}'
TO siem.rule_performance_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    security_rule_id AS rule_id,
    security_rule_name AS rule_name,
    security_rule_type AS rule_type,
    count() AS match_count,
    countIf(event_type = 'ALERT') AS alert_count,
    0 AS true_positive_count,  -- Updated via alert feedback
    0 AS false_positive_count,
    0 AS unresolved_count,
    uniqState(principal_hostname) AS unique_hosts_state,
    uniqState(principal_user_id) AS unique_users_state,
    groupUniqArray(10)(mitre_tactics) AS mitre_tactics,
    groupUniqArray(10)(mitre_techniques) AS mitre_techniques
FROM siem.events
WHERE security_rule_id != ''
GROUP BY tenant_id, hour, rule_id, rule_name, rule_type;

-- ============================================================================
-- 6. GeoIP Statistics
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.geo_stats_hourly ON CLUSTER '{cluster}'
(
    tenant_id                       String,
    hour                            DateTime,
    country                         LowCardinality(String),
    direction                       Enum8('INBOUND' = 1, 'OUTBOUND' = 2),

    -- Counts
    event_count                     UInt64,
    connection_count                UInt64,
    bytes_total                     UInt64,

    -- Unique counts
    unique_ips_state                AggregateFunction(uniq, IPv6),

    -- Threat indicators
    ti_matched_count                UInt64,
    blocked_count                   UInt64
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/siem/geo_stats_hourly', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, direction, country)
TTL hour + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

-- Inbound (external sources)
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.geo_stats_inbound_mv ON CLUSTER '{cluster}'
TO siem.geo_stats_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    principal_geo_country AS country,
    CAST('INBOUND' AS Enum8('INBOUND' = 1, 'OUTBOUND' = 2)) AS direction,
    count() AS event_count,
    countIf(event_type IN ('NETWORK_CONNECTION', 'NETWORK_FLOW')) AS connection_count,
    sum(network_received_bytes) AS bytes_total,
    uniqState(arrayJoin(principal_ip)) AS unique_ips_state,
    sum(ti_matched) AS ti_matched_count,
    countIf(security_action = 'BLOCK') AS blocked_count
FROM siem.events
WHERE principal_geo_country != '' AND network_direction = 'INBOUND'
GROUP BY tenant_id, hour, country;

-- Outbound (internal to external)
CREATE MATERIALIZED VIEW IF NOT EXISTS siem.geo_stats_outbound_mv ON CLUSTER '{cluster}'
TO siem.geo_stats_hourly
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    target_geo_country AS country,
    CAST('OUTBOUND' AS Enum8('INBOUND' = 1, 'OUTBOUND' = 2)) AS direction,
    count() AS event_count,
    countIf(event_type IN ('NETWORK_CONNECTION', 'NETWORK_FLOW')) AS connection_count,
    sum(network_sent_bytes) AS bytes_total,
    uniqState(arrayJoin(target_ip)) AS unique_ips_state,
    sum(ti_matched) AS ti_matched_count,
    countIf(security_action = 'BLOCK') AS blocked_count
FROM siem.events
WHERE target_geo_country != '' AND network_direction = 'OUTBOUND'
GROUP BY tenant_id, hour, country;

-- ============================================================================
-- Distributed Tables for Materialized Views
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.events_hourly_distributed ON CLUSTER '{cluster}'
AS siem.events_hourly
ENGINE = Distributed('{cluster}', 'siem', 'events_hourly', rand());

CREATE TABLE IF NOT EXISTS siem.events_daily_distributed ON CLUSTER '{cluster}'
AS siem.events_daily
ENGINE = Distributed('{cluster}', 'siem', 'events_daily', rand());

CREATE TABLE IF NOT EXISTS siem.top_talkers_hourly_distributed ON CLUSTER '{cluster}'
AS siem.top_talkers_hourly
ENGINE = Distributed('{cluster}', 'siem', 'top_talkers_hourly', rand());

CREATE TABLE IF NOT EXISTS siem.user_activity_hourly_distributed ON CLUSTER '{cluster}'
AS siem.user_activity_hourly
ENGINE = Distributed('{cluster}', 'siem', 'user_activity_hourly', rand());

CREATE TABLE IF NOT EXISTS siem.rule_performance_hourly_distributed ON CLUSTER '{cluster}'
AS siem.rule_performance_hourly
ENGINE = Distributed('{cluster}', 'siem', 'rule_performance_hourly', rand());

CREATE TABLE IF NOT EXISTS siem.geo_stats_hourly_distributed ON CLUSTER '{cluster}'
AS siem.geo_stats_hourly
ENGINE = Distributed('{cluster}', 'siem', 'geo_stats_hourly', rand());

-- ============================================================================
-- Query Examples
-- ============================================================================
--
-- -- Get hourly event counts for last 24 hours
-- SELECT
--     hour,
--     sum(event_count) AS total_events,
--     uniqMerge(unique_hosts_state) AS unique_hosts
-- FROM siem.events_hourly_distributed
-- WHERE tenant_id = 'tenant-001'
--   AND hour >= now() - INTERVAL 24 HOUR
-- GROUP BY hour
-- ORDER BY hour;
--
-- -- Top 10 source IPs by event count
-- SELECT
--     ip_address,
--     sum(event_count) AS total_events,
--     sum(bytes_total) AS total_bytes
-- FROM siem.top_talkers_hourly_distributed
-- WHERE tenant_id = 'tenant-001'
--   AND hour >= now() - INTERVAL 24 HOUR
--   AND ip_role = 'SOURCE'
-- GROUP BY ip_address
-- ORDER BY total_events DESC
-- LIMIT 10;
--
-- -- User activity summary
-- SELECT
--     user_id,
--     sum(login_count) AS logins,
--     sum(failed_login_count) AS failed_logins,
--     sum(alert_count) AS alerts
-- FROM siem.user_activity_hourly_distributed
-- WHERE tenant_id = 'tenant-001'
--   AND hour >= now() - INTERVAL 7 DAY
-- GROUP BY user_id
-- HAVING alerts > 0
-- ORDER BY alerts DESC;

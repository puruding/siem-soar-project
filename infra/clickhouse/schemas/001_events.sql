-- ============================================================================
-- SIEM-SOAR Platform: Events Table Schema
-- ============================================================================
-- Table: siem.events
-- Purpose: Primary security event storage with UDM (Unified Data Model)
-- Engine: ReplicatedMergeTree for HA and scalability
-- Partitioning: Daily by timestamp
-- TTL: 90 days (configurable via ALTER)
-- ============================================================================

-- Drop existing table if needed (for development only, comment in production)
-- DROP TABLE IF EXISTS siem.events ON CLUSTER '{cluster}';

CREATE TABLE IF NOT EXISTS siem.events ON CLUSTER '{cluster}'
(
    -- ========================================================================
    -- Core Identity Fields
    -- ========================================================================
    event_id                        UUID DEFAULT generateUUIDv4(),
    tenant_id                       String,

    -- ========================================================================
    -- Metadata
    -- ========================================================================
    timestamp                       DateTime64(3, 'UTC'),
    collected_timestamp             DateTime64(3, 'UTC') DEFAULT now64(3),
    ingestion_timestamp             DateTime64(3, 'UTC') DEFAULT now64(3),

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
    product_version                 String DEFAULT '',
    product_event_type              String DEFAULT '',
    description                     String DEFAULT '',
    log_type                        LowCardinality(String) DEFAULT '',

    -- ========================================================================
    -- Principal (Source/Actor)
    -- ========================================================================
    principal_hostname              String DEFAULT '',
    principal_ip                    Array(IPv6),
    principal_mac                   Array(String),
    principal_port                  UInt16 DEFAULT 0,
    principal_asset_id              String DEFAULT '',

    -- Principal User
    principal_user_id               String DEFAULT '',
    principal_user_display_name     String DEFAULT '',
    principal_user_email            Array(String),
    principal_user_groups           Array(String),
    principal_user_windows_sid      String DEFAULT '',
    principal_domain                String DEFAULT '',

    -- Principal Process
    principal_process_pid           UInt64 DEFAULT 0,
    principal_process_name          String DEFAULT '',
    principal_process_path          String DEFAULT '',
    principal_process_sha256        FixedString(64) DEFAULT '',
    principal_process_md5           FixedString(32) DEFAULT '',
    principal_process_sha1          FixedString(40) DEFAULT '',
    principal_process_command_line  String DEFAULT '',

    -- Principal Parent Process
    principal_parent_process_pid    UInt64 DEFAULT 0,
    principal_parent_process_name   String DEFAULT '',
    principal_parent_process_path   String DEFAULT '',
    principal_parent_process_sha256 FixedString(64) DEFAULT '',
    principal_parent_process_command_line String DEFAULT '',

    -- Principal Platform
    principal_platform              Enum8(
                                        'UNKNOWN' = 0,
                                        'WINDOWS' = 1,
                                        'LINUX' = 2,
                                        'MAC' = 3,
                                        'ANDROID' = 4,
                                        'IOS' = 5,
                                        'CHROMEOS' = 6
                                    ) DEFAULT 'UNKNOWN',
    principal_platform_version      String DEFAULT '',

    -- ========================================================================
    -- Target (Destination)
    -- ========================================================================
    target_hostname                 String DEFAULT '',
    target_ip                       Array(IPv6),
    target_mac                      Array(String),
    target_port                     UInt16 DEFAULT 0,
    target_asset_id                 String DEFAULT '',
    target_url                      String DEFAULT '',
    target_application              String DEFAULT '',

    -- Target User
    target_user_id                  String DEFAULT '',
    target_user_display_name        String DEFAULT '',
    target_user_email               Array(String),
    target_user_groups              Array(String),
    target_user_windows_sid         String DEFAULT '',
    target_domain                   String DEFAULT '',

    -- Target Process
    target_process_pid              UInt64 DEFAULT 0,
    target_process_name             String DEFAULT '',
    target_process_path             String DEFAULT '',
    target_process_sha256           FixedString(64) DEFAULT '',
    target_process_command_line     String DEFAULT '',

    -- Target File
    target_file_path                String DEFAULT '',
    target_file_name                String DEFAULT '',
    target_file_sha256              FixedString(64) DEFAULT '',
    target_file_md5                 FixedString(32) DEFAULT '',
    target_file_sha1                FixedString(40) DEFAULT '',
    target_file_size                UInt64 DEFAULT 0,
    target_file_mime_type           String DEFAULT '',

    -- Target Registry (Windows)
    target_registry_key             String DEFAULT '',
    target_registry_value_name      String DEFAULT '',
    target_registry_value_data      String DEFAULT '',

    -- Target Resource
    target_resource_name            String DEFAULT '',
    target_resource_type            String DEFAULT '',
    target_resource_id              String DEFAULT '',

    -- ========================================================================
    -- Network
    -- ========================================================================
    network_application_protocol    Enum8(
                                        'UNKNOWN' = 0,
                                        'HTTP' = 1,
                                        'HTTPS' = 2,
                                        'DNS' = 3,
                                        'DHCP' = 4,
                                        'SSH' = 5,
                                        'RDP' = 6,
                                        'SMB' = 7,
                                        'LDAP' = 8,
                                        'KERBEROS' = 9,
                                        'FTP' = 10,
                                        'SMTP' = 11,
                                        'IMAP' = 12,
                                        'POP3' = 13,
                                        'NTP' = 14,
                                        'SNMP' = 15
                                    ) DEFAULT 'UNKNOWN',
    network_direction               Enum8(
                                        'UNKNOWN' = 0,
                                        'INBOUND' = 1,
                                        'OUTBOUND' = 2
                                    ) DEFAULT 'UNKNOWN',
    network_ip_protocol             Enum8(
                                        'UNKNOWN' = 0,
                                        'ICMP' = 1,
                                        'TCP' = 6,
                                        'UDP' = 17,
                                        'GRE' = 47,
                                        'ESP' = 50,
                                        'AH' = 51
                                    ) DEFAULT 'UNKNOWN',
    network_received_bytes          UInt64 DEFAULT 0,
    network_sent_bytes              UInt64 DEFAULT 0,
    network_received_packets        UInt64 DEFAULT 0,
    network_sent_packets            UInt64 DEFAULT 0,
    network_session_duration        Float64 DEFAULT 0,
    network_session_id              String DEFAULT '',

    -- Network DNS
    network_dns_questions           Nested(
                                        name String,
                                        type UInt16
                                    ),
    network_dns_answers             Nested(
                                        name String,
                                        type UInt16,
                                        data String,
                                        ttl UInt32
                                    ),
    network_dns_response_code       UInt8 DEFAULT 0,

    -- Network HTTP
    network_http_method             LowCardinality(String) DEFAULT '',
    network_http_referral_url       String DEFAULT '',
    network_http_response_code      UInt16 DEFAULT 0,
    network_http_user_agent         String DEFAULT '',

    -- Network Email
    network_email_from              String DEFAULT '',
    network_email_to                Array(String),
    network_email_cc                Array(String),
    network_email_subject           String DEFAULT '',
    network_email_attachments       Array(String),

    -- Network TLS
    network_tls_cipher              String DEFAULT '',
    network_tls_version             String DEFAULT '',
    network_tls_ja3                 FixedString(32) DEFAULT '',
    network_tls_ja3s                FixedString(32) DEFAULT '',
    network_tls_cert_serial         String DEFAULT '',
    network_tls_cert_issuer         String DEFAULT '',
    network_tls_cert_subject        String DEFAULT '',
    network_tls_cert_not_before     DateTime64(3, 'UTC') DEFAULT toDateTime64(0, 3),
    network_tls_cert_not_after      DateTime64(3, 'UTC') DEFAULT toDateTime64(0, 3),

    -- ========================================================================
    -- Security Result
    -- ========================================================================
    security_action                 Enum8(
                                        'UNKNOWN' = 0,
                                        'ALLOW' = 1,
                                        'BLOCK' = 2,
                                        'QUARANTINE' = 3,
                                        'CHALLENGE' = 4,
                                        'ALERT' = 5
                                    ) DEFAULT 'UNKNOWN',
    security_severity               Enum8(
                                        'UNKNOWN' = 0,
                                        'INFORMATIONAL' = 1,
                                        'LOW' = 2,
                                        'MEDIUM' = 3,
                                        'HIGH' = 4,
                                        'CRITICAL' = 5
                                    ) DEFAULT 'UNKNOWN',
    security_confidence             Float32 DEFAULT 0,
    security_category               LowCardinality(String) DEFAULT '',
    security_category_details       Array(String),

    -- Security Rule
    security_rule_id                String DEFAULT '',
    security_rule_name              String DEFAULT '',
    security_rule_type              Enum8(
                                        'UNKNOWN' = 0,
                                        'SIGMA' = 1,
                                        'YARA' = 2,
                                        'CUSTOM' = 3,
                                        'ML' = 4,
                                        'CORRELATION' = 5,
                                        'IOC' = 6
                                    ) DEFAULT 'UNKNOWN',
    security_rule_version           String DEFAULT '',

    -- Security Threat
    security_threat_id              String DEFAULT '',
    security_threat_name            String DEFAULT '',
    security_threat_status          String DEFAULT '',

    -- Detection Fields (key-value pairs)
    security_detection_fields       Map(String, String),

    -- Alert State
    security_alert_state            Enum8(
                                        'UNKNOWN' = 0,
                                        'NEW' = 1,
                                        'TRIAGED' = 2,
                                        'IN_PROGRESS' = 3,
                                        'RESOLVED' = 4,
                                        'CLOSED' = 5,
                                        'FALSE_POSITIVE' = 6
                                    ) DEFAULT 'NEW',
    security_url_back_to_product    String DEFAULT '',

    -- ========================================================================
    -- Enrichment & Labels
    -- ========================================================================
    base_labels                     Map(String, String),
    enrichment_labels               Map(String, String),

    -- GeoIP Enrichment (Principal)
    principal_geo_country           LowCardinality(String) DEFAULT '',
    principal_geo_city              String DEFAULT '',
    principal_geo_latitude          Float32 DEFAULT 0,
    principal_geo_longitude         Float32 DEFAULT 0,
    principal_geo_asn               UInt32 DEFAULT 0,
    principal_geo_asn_org           String DEFAULT '',

    -- GeoIP Enrichment (Target)
    target_geo_country              LowCardinality(String) DEFAULT '',
    target_geo_city                 String DEFAULT '',
    target_geo_latitude             Float32 DEFAULT 0,
    target_geo_longitude            Float32 DEFAULT 0,
    target_geo_asn                  UInt32 DEFAULT 0,
    target_geo_asn_org              String DEFAULT '',

    -- TI Enrichment
    ti_matched                      UInt8 DEFAULT 0,
    ti_ioc_types                    Array(String),
    ti_feed_names                   Array(String),
    ti_threat_types                 Array(String),
    ti_confidence                   Float32 DEFAULT 0,

    -- Asset Enrichment
    principal_asset_type            LowCardinality(String) DEFAULT '',
    principal_asset_criticality     Enum8(
                                        'UNKNOWN' = 0,
                                        'LOW' = 1,
                                        'MEDIUM' = 2,
                                        'HIGH' = 3,
                                        'CRITICAL' = 4
                                    ) DEFAULT 'UNKNOWN',
    principal_asset_owner           String DEFAULT '',
    principal_asset_department      String DEFAULT '',
    target_asset_type               LowCardinality(String) DEFAULT '',
    target_asset_criticality        Enum8(
                                        'UNKNOWN' = 0,
                                        'LOW' = 1,
                                        'MEDIUM' = 2,
                                        'HIGH' = 3,
                                        'CRITICAL' = 4
                                    ) DEFAULT 'UNKNOWN',
    target_asset_owner              String DEFAULT '',
    target_asset_department         String DEFAULT '',

    -- ========================================================================
    -- Raw Data
    -- ========================================================================
    raw_log                         String DEFAULT '' CODEC(ZSTD(3)),

    -- ========================================================================
    -- MITRE ATT&CK Mapping
    -- ========================================================================
    mitre_tactics                   Array(LowCardinality(String)),
    mitre_techniques                Array(LowCardinality(String)),
    mitre_sub_techniques            Array(LowCardinality(String))
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem/events', '{replica}')
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, event_type, timestamp, sipHash64(event_id))
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 10485760,
    min_rows_for_wide_part = 0,
    ttl_only_drop_parts = 1,
    storage_policy = 'default';

-- ============================================================================
-- Secondary Indexes
-- ============================================================================

-- IP Address Indexes (Bloom Filter for exact match)
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_principal_ip principal_ip TYPE bloom_filter GRANULARITY 4;

ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_target_ip target_ip TYPE bloom_filter GRANULARITY 4;

-- Hash Indexes (Bloom Filter for exact match)
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_principal_sha256 principal_process_sha256 TYPE bloom_filter GRANULARITY 4;

ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_target_file_sha256 target_file_sha256 TYPE bloom_filter GRANULARITY 4;

-- User ID Index
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_principal_user principal_user_id TYPE bloom_filter GRANULARITY 4;

-- Hostname Indexes
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_principal_hostname principal_hostname TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;

ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_target_hostname target_hostname TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;

-- Severity Index (Set for low-cardinality)
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_severity security_severity TYPE set(10) GRANULARITY 4;

-- Command Line Index (Token for substring search)
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_cmdline principal_process_command_line TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;

-- Rule Name Index
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_rule_name security_rule_name TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;

-- Vendor/Product Index
ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_vendor vendor_name TYPE set(100) GRANULARITY 4;

ALTER TABLE siem.events ON CLUSTER '{cluster}'
    ADD INDEX idx_product product_name TYPE set(500) GRANULARITY 4;

-- ============================================================================
-- Distributed Table (for querying across shards)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem.events_distributed ON CLUSTER '{cluster}'
AS siem.events
ENGINE = Distributed('{cluster}', 'siem', 'events', rand());

-- ============================================================================
-- Comments
-- ============================================================================
-- Use events_distributed for queries, events for direct inserts
--
-- Example Insert:
-- INSERT INTO siem.events (tenant_id, timestamp, event_type, vendor_name, product_name, ...)
--
-- Example Query:
-- SELECT * FROM siem.events_distributed
-- WHERE tenant_id = 'tenant-001'
--   AND event_type = 'USER_LOGIN'
--   AND timestamp >= now() - INTERVAL 1 DAY
-- ORDER BY timestamp DESC
-- LIMIT 100

-- ============================================================================
-- SIEM-SOAR Platform: Metrics Tables Schema
-- ============================================================================
-- Database: siem_metrics
-- Purpose: Time-series metrics for performance monitoring and analytics
-- Engine: ReplicatedMergeTree for HA
-- Partitioning: Monthly for raw, yearly for aggregated
-- ============================================================================

-- ============================================================================
-- 1. System Metrics (Platform Health)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.system_metrics ON CLUSTER '{cluster}'
(
    timestamp                       DateTime64(3, 'UTC'),
    service_name                    LowCardinality(String),
    instance_id                     String,
    host                            String,

    -- CPU Metrics
    cpu_usage_percent               Float32,
    cpu_system_percent              Float32,
    cpu_user_percent                Float32,
    cpu_iowait_percent              Float32,

    -- Memory Metrics
    memory_used_bytes               UInt64,
    memory_total_bytes              UInt64,
    memory_percent                  Float32,

    -- Disk Metrics
    disk_used_bytes                 UInt64,
    disk_total_bytes                UInt64,
    disk_read_bytes_per_sec         UInt64,
    disk_write_bytes_per_sec        UInt64,
    disk_read_ops_per_sec           UInt64,
    disk_write_ops_per_sec          UInt64,

    -- Network Metrics
    network_rx_bytes_per_sec        UInt64,
    network_tx_bytes_per_sec        UInt64,
    network_rx_packets_per_sec      UInt64,
    network_tx_packets_per_sec      UInt64,
    network_rx_errors               UInt64,
    network_tx_errors               UInt64,

    -- Process Metrics
    process_count                   UInt32,
    thread_count                    UInt32,
    open_file_descriptors           UInt32,

    -- Labels
    labels                          Map(String, String)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem_metrics/system_metrics', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (service_name, instance_id, timestamp)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- 2. Pipeline Metrics (Data Ingestion)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.pipeline_metrics ON CLUSTER '{cluster}'
(
    timestamp                       DateTime64(3, 'UTC'),
    tenant_id                       String,
    pipeline_name                   LowCardinality(String),
    stage_name                      LowCardinality(String),  -- collector, parser, normalizer, enricher, router
    instance_id                     String,

    -- Throughput Metrics
    events_received                 UInt64,
    events_processed                UInt64,
    events_dropped                  UInt64,
    events_failed                   UInt64,
    bytes_received                  UInt64,
    bytes_processed                 UInt64,

    -- Latency Metrics (milliseconds)
    latency_p50                     Float32,
    latency_p90                     Float32,
    latency_p99                     Float32,
    latency_max                     Float32,

    -- Queue Metrics
    queue_size                      UInt64,
    queue_capacity                  UInt64,

    -- Error Metrics
    parse_errors                    UInt64,
    validation_errors               UInt64,
    enrichment_errors               UInt64,

    -- Rate Metrics
    events_per_second               Float32,
    bytes_per_second                Float32,

    -- Source Breakdown
    source_type                     LowCardinality(String) DEFAULT '',
    source_vendor                   LowCardinality(String) DEFAULT '',

    labels                          Map(String, String)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem_metrics/pipeline_metrics', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, pipeline_name, stage_name, timestamp)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- 3. Detection Metrics (Rule Execution)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.detection_metrics ON CLUSTER '{cluster}'
(
    timestamp                       DateTime64(3, 'UTC'),
    tenant_id                       String,

    -- Rule Identification
    rule_id                         String,
    rule_name                       String,
    rule_type                       LowCardinality(String),  -- sigma, yara, custom, ml, correlation
    rule_severity                   LowCardinality(String),

    -- Execution Metrics
    executions                      UInt64,
    matches                         UInt64,
    alerts_generated                UInt64,
    events_evaluated                UInt64,

    -- Performance Metrics
    execution_time_ms_avg           Float32,
    execution_time_ms_p99           Float32,
    execution_time_ms_max           Float32,
    memory_used_bytes_avg           UInt64,

    -- Quality Metrics
    true_positives                  UInt64,
    false_positives                 UInt64,
    feedback_count                  UInt64,
    precision                       Float32,  -- Computed: TP / (TP + FP)

    -- Error Metrics
    errors                          UInt64,
    timeouts                        UInt64,

    labels                          Map(String, String)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem_metrics/detection_metrics', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, rule_id, timestamp)
TTL timestamp + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- 4. AI/ML Metrics (Model Performance)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.ml_metrics ON CLUSTER '{cluster}'
(
    timestamp                       DateTime64(3, 'UTC'),
    tenant_id                       String,

    -- Model Identification
    model_id                        String,
    model_name                      String,
    model_version                   String,
    model_type                      LowCardinality(String),  -- classifier, anomaly, nlp, etc.

    -- Inference Metrics
    inferences                      UInt64,
    batch_size_avg                  Float32,

    -- Latency Metrics
    latency_ms_p50                  Float32,
    latency_ms_p90                  Float32,
    latency_ms_p99                  Float32,

    -- Classification Metrics
    predictions_total               UInt64,
    predictions_positive            UInt64,
    predictions_negative            UInt64,
    confidence_avg                  Float32,
    confidence_p50                  Float32,

    -- Quality Metrics (from feedback)
    accuracy                        Float32,
    precision_score                 Float32,
    recall                          Float32,
    f1_score                        Float32,
    auc_roc                         Float32,

    -- Resource Metrics
    gpu_memory_used_bytes           UInt64,
    gpu_utilization_percent         Float32,
    cpu_time_ms                     Float32,

    -- Drift Metrics
    feature_drift_score             Float32,
    prediction_drift_score          Float32,

    labels                          Map(String, String)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem_metrics/ml_metrics', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, model_id, timestamp)
TTL timestamp + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- 5. SOAR Metrics (Automation & Response)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.soar_metrics ON CLUSTER '{cluster}'
(
    timestamp                       DateTime64(3, 'UTC'),
    tenant_id                       String,

    -- Playbook Identification
    playbook_id                     String,
    playbook_name                   String,
    playbook_version                String,

    -- Execution Metrics
    executions_started              UInt64,
    executions_completed            UInt64,
    executions_failed               UInt64,
    executions_cancelled            UInt64,
    executions_pending_approval     UInt64,

    -- Duration Metrics
    duration_ms_avg                 Float32,
    duration_ms_p50                 Float32,
    duration_ms_p99                 Float32,
    duration_ms_max                 Float32,

    -- Action Metrics
    actions_executed                UInt64,
    actions_succeeded               UInt64,
    actions_failed                  UInt64,

    -- Approval Metrics
    approvals_requested             UInt64,
    approvals_granted               UInt64,
    approvals_denied                UInt64,
    approval_time_ms_avg            Float32,

    -- Impact Metrics
    alerts_processed                UInt64,
    alerts_resolved                 UInt64,
    time_saved_hours                Float32,  -- Estimated

    -- Connector Metrics
    connector_calls                 UInt64,
    connector_errors                UInt64,

    labels                          Map(String, String)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem_metrics/soar_metrics', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, playbook_id, timestamp)
TTL timestamp + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- 6. Query Metrics (Search Performance)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.query_metrics ON CLUSTER '{cluster}'
(
    timestamp                       DateTime64(3, 'UTC'),
    tenant_id                       String,
    user_id                         String,

    -- Query Identification
    query_id                        UUID,
    query_type                      LowCardinality(String),  -- search, aggregation, timeline, etc.
    query_source                    LowCardinality(String),  -- ui, api, scheduled, copilot

    -- Execution Metrics
    execution_time_ms               Float32,
    rows_read                       UInt64,
    rows_returned                   UInt64,
    bytes_read                      UInt64,

    -- Query Complexity
    time_range_hours                Float32,
    filter_count                    UInt16,
    aggregation_count               UInt16,
    tables_accessed                 Array(String),

    -- Resource Usage
    memory_used_bytes               UInt64,
    cpu_time_ms                     Float32,

    -- Status
    status                          Enum8('SUCCESS' = 0, 'TIMEOUT' = 1, 'ERROR' = 2, 'CANCELLED' = 3),
    error_message                   String DEFAULT '',

    -- Cache
    cache_hit                       UInt8 DEFAULT 0,

    -- Query Hash (for deduplication/analysis)
    query_hash                      UInt64,

    labels                          Map(String, String)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/siem_metrics/query_metrics', '{replica}')
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, query_type)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- 7. Tenant Metrics (Usage & Billing)
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.tenant_metrics ON CLUSTER '{cluster}'
(
    date                            Date,
    tenant_id                       String,

    -- Volume Metrics
    events_ingested                 UInt64,
    bytes_ingested                  UInt64,
    events_stored                   UInt64,
    bytes_stored                    UInt64,

    -- Alert Metrics
    alerts_generated                UInt64,
    alerts_resolved                 UInt64,
    alerts_open                     UInt64,

    -- Detection Metrics
    rules_active                    UInt32,
    rules_triggered                 UInt32,

    -- SOAR Metrics
    playbooks_active                UInt32,
    playbook_executions             UInt64,

    -- User Metrics
    active_users                    UInt32,
    queries_executed                UInt64,
    api_calls                       UInt64,

    -- AI Metrics
    ai_inferences                   UInt64,
    ai_tokens_used                  UInt64,

    -- Storage Metrics
    retention_days                  UInt16,
    total_storage_bytes             UInt64,

    -- Feature Usage
    features_used                   Array(String)
)
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/siem_metrics/tenant_metrics', '{replica}')
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, date)
TTL date + INTERVAL 3 YEAR DELETE
SETTINGS index_granularity = 8192;

-- ============================================================================
-- Materialized Views for Aggregation
-- ============================================================================

-- Pipeline Hourly Aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS siem_metrics.pipeline_hourly_mv ON CLUSTER '{cluster}'
TO siem_metrics.pipeline_hourly
AS SELECT
    toStartOfHour(timestamp) AS hour,
    tenant_id,
    pipeline_name,
    stage_name,
    sum(events_received) AS events_received,
    sum(events_processed) AS events_processed,
    sum(events_dropped) AS events_dropped,
    sum(bytes_received) AS bytes_received,
    avg(latency_p50) AS latency_p50_avg,
    max(latency_max) AS latency_max,
    sum(parse_errors + validation_errors + enrichment_errors) AS total_errors
FROM siem_metrics.pipeline_metrics
GROUP BY hour, tenant_id, pipeline_name, stage_name;

CREATE TABLE IF NOT EXISTS siem_metrics.pipeline_hourly ON CLUSTER '{cluster}'
(
    hour                            DateTime,
    tenant_id                       String,
    pipeline_name                   LowCardinality(String),
    stage_name                      LowCardinality(String),
    events_received                 UInt64,
    events_processed                UInt64,
    events_dropped                  UInt64,
    bytes_received                  UInt64,
    latency_p50_avg                 Float32,
    latency_max                     Float32,
    total_errors                    UInt64
)
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/siem_metrics/pipeline_hourly', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, pipeline_name, stage_name, hour)
TTL hour + INTERVAL 2 YEAR DELETE;

-- ============================================================================
-- Distributed Tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS siem_metrics.system_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.system_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'system_metrics', rand());

CREATE TABLE IF NOT EXISTS siem_metrics.pipeline_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.pipeline_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'pipeline_metrics', rand());

CREATE TABLE IF NOT EXISTS siem_metrics.detection_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.detection_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'detection_metrics', rand());

CREATE TABLE IF NOT EXISTS siem_metrics.ml_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.ml_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'ml_metrics', rand());

CREATE TABLE IF NOT EXISTS siem_metrics.soar_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.soar_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'soar_metrics', rand());

CREATE TABLE IF NOT EXISTS siem_metrics.query_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.query_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'query_metrics', rand());

CREATE TABLE IF NOT EXISTS siem_metrics.tenant_metrics_distributed ON CLUSTER '{cluster}'
AS siem_metrics.tenant_metrics
ENGINE = Distributed('{cluster}', 'siem_metrics', 'tenant_metrics', rand());

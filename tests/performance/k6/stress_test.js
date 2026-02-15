/**
 * K6 Stress Test for SIEM/SOAR Platform
 *
 * This test pushes the system beyond normal limits to identify breaking points.
 * Goal: Find the maximum sustainable load and identify bottlenecks.
 */

import http from 'k6/http';
import { check, sleep, group, fail } from 'k6';
import { Rate, Counter, Trend, Gauge } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const eventsIngested = new Counter('events_ingested');
const breakingPointReached = new Gauge('breaking_point_reached');
const responseTimeP99 = new Trend('response_time_p99');
const concurrentConnections = new Gauge('concurrent_connections');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const GATEWAY_URL = __ENV.GATEWAY_URL || 'http://localhost:8080';
const COLLECTOR_URL = __ENV.COLLECTOR_URL || 'http://localhost:8086';

// Stress test configuration - aggressive ramp-up
export const options = {
    scenarios: {
        stress_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                // Warm up
                { duration: '2m', target: 100 },
                // Push limits
                { duration: '5m', target: 300 },
                { duration: '5m', target: 500 },
                { duration: '5m', target: 700 },
                { duration: '5m', target: 1000 },
                // Maximum stress
                { duration: '10m', target: 1500 },
                // Recovery observation
                { duration: '5m', target: 500 },
                { duration: '2m', target: 0 },
            ],
            gracefulRampDown: '30s',
        },
    },
    thresholds: {
        // Looser thresholds for stress testing - we expect some degradation
        'http_req_duration': ['p(95)<2000', 'p(99)<5000'],
        'http_req_failed': ['rate<0.10'],  // Allow up to 10% error rate
        'errors': ['rate<0.15'],
    },
};

// Generate large batch of events for stress
function generateLargeEventBatch(size = 500) {
    const eventTypes = ['auth_failure', 'auth_success', 'connection', 'process_create', 'file_access', 'dns_query', 'network_flow'];
    const events = [];

    for (let i = 0; i < size; i++) {
        events.push({
            timestamp: new Date().toISOString(),
            event_id: randomString(32),
            event_type: eventTypes[randomIntBetween(0, eventTypes.length - 1)],
            source: {
                ip: `192.168.${randomIntBetween(1, 254)}.${randomIntBetween(1, 254)}`,
                port: randomIntBetween(1024, 65535)
            },
            destination: {
                ip: `10.0.${randomIntBetween(0, 255)}.${randomIntBetween(1, 254)}`,
                port: randomIntBetween(1, 1024)
            },
            user: { name: `user${randomIntBetween(1, 10000)}` },
            message: randomString(200),  // Larger message for stress
            raw_log: randomString(1000),  // Include raw log data
            metadata: {
                collector_id: `collector-${randomIntBetween(1, 100)}`,
                tags: Array(10).fill(0).map(() => randomString(10))  // Many tags
            }
        });
    }
    return events;
}

// Stress event ingestion with large batches
function stressEventIngestion() {
    const batchSizes = [100, 250, 500, 1000];
    const batchSize = batchSizes[randomIntBetween(0, batchSizes.length - 1)];
    const events = generateLargeEventBatch(batchSize);

    const response = http.post(
        `${COLLECTOR_URL}/api/v1/events/batch`,
        JSON.stringify({ events: events }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'stress_event_ingestion' },
            timeout: '60s'
        }
    );

    responseTimeP99.add(response.timings.duration);

    const success = check(response, {
        'stress ingestion status is 2xx': (r) => r.status >= 200 && r.status < 300,
        'stress ingestion time < 5s': (r) => r.timings.duration < 5000,
    });

    if (success) {
        eventsIngested.add(batchSize);
    } else {
        errorRate.add(1);
        if (response.status >= 500) {
            breakingPointReached.add(1);
        }
    }

    return response;
}

// Stress queries with complex operations
function stressQueryExecution() {
    const complexQueries = [
        // Heavy aggregation
        `SELECT
            src_ip,
            dst_ip,
            event_type,
            count(*) as event_count,
            countDistinct(user) as unique_users,
            min(timestamp) as first_seen,
            max(timestamp) as last_seen
         FROM events
         WHERE timestamp >= now() - INTERVAL 6 HOUR
         GROUP BY src_ip, dst_ip, event_type
         HAVING event_count > 10
         ORDER BY event_count DESC
         LIMIT 1000`,

        // Join-like query
        `SELECT
            a.src_ip,
            count(*) as failure_count
         FROM events a
         WHERE a.event_type = 'auth_failure'
           AND a.timestamp >= now() - INTERVAL 1 HOUR
           AND a.src_ip IN (
               SELECT src_ip FROM events
               WHERE event_type = 'auth_success'
               AND timestamp >= now() - INTERVAL 1 HOUR
           )
         GROUP BY a.src_ip
         ORDER BY failure_count DESC
         LIMIT 100`,

        // Time series with high granularity
        `SELECT
            toStartOfSecond(timestamp) as second,
            count(*) as events,
            countDistinct(src_ip) as unique_sources
         FROM events
         WHERE timestamp >= now() - INTERVAL 10 MINUTE
         GROUP BY second
         ORDER BY second`,

        // Full text search simulation
        `SELECT *
         FROM events
         WHERE message LIKE '%error%'
           OR message LIKE '%failure%'
           OR message LIKE '%denied%'
         ORDER BY timestamp DESC
         LIMIT 1000`
    ];

    const query = complexQueries[randomIntBetween(0, complexQueries.length - 1)];

    const response = http.post(
        `${GATEWAY_URL}/api/v1/query`,
        JSON.stringify({
            query: query,
            start_time: new Date(Date.now() - 6 * 3600000).toISOString(),
            end_time: new Date().toISOString(),
            timeout: 30
        }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'stress_query' },
            timeout: '60s'
        }
    );

    responseTimeP99.add(response.timings.duration);

    check(response, {
        'stress query status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    if (response.status >= 500) {
        errorRate.add(1);
        breakingPointReached.add(1);
    }

    return response;
}

// Stress concurrent alert operations
function stressAlertOperations() {
    const operations = [
        () => http.get(`${GATEWAY_URL}/api/v1/alerts?limit=100`, { tags: { name: 'stress_alert_list' } }),
        () => http.get(`${GATEWAY_URL}/api/v1/alerts/statistics`, { tags: { name: 'stress_alert_stats' } }),
        () => http.post(
            `${GATEWAY_URL}/api/v1/alerts/search`,
            JSON.stringify({
                query: randomString(20),
                filters: {
                    severity: ['high', 'critical'],
                    status: ['new', 'investigating']
                },
                limit: 50
            }),
            { headers: { 'Content-Type': 'application/json' }, tags: { name: 'stress_alert_search' } }
        )
    ];

    const operation = operations[randomIntBetween(0, operations.length - 1)];
    const response = operation();

    responseTimeP99.add(response.timings.duration);

    check(response, {
        'stress alert operation status is 2xx': (r) => r.status >= 200 && r.status < 300 || r.status === 404,
    });

    return response;
}

// Stress playbook operations
function stressPlaybookOperations() {
    // Trigger multiple playbook executions
    const response = http.post(
        `${GATEWAY_URL}/api/v1/playbooks/stress-test-playbook/execute`,
        JSON.stringify({
            trigger_data: {
                alert_id: randomString(32),
                severity: 'high'
            }
        }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'stress_playbook_execution' }
        }
    );

    responseTimeP99.add(response.timings.duration);

    check(response, {
        'stress playbook execution accepted': (r) => r.status === 202 || r.status === 200 || r.status === 404,
    });

    return response;
}

// Burst traffic simulation
function burstTraffic() {
    const requests = [];
    const burstSize = 50;  // Concurrent requests in burst

    for (let i = 0; i < burstSize; i++) {
        requests.push(['GET', `${GATEWAY_URL}/api/v1/alerts?limit=10`, null, { tags: { name: 'burst_request' } }]);
    }

    const responses = http.batch(requests);

    let successCount = 0;
    responses.forEach(r => {
        if (r.status >= 200 && r.status < 300) {
            successCount++;
        } else {
            errorRate.add(1);
        }
        responseTimeP99.add(r.timings.duration);
    });

    check(successCount, {
        'burst: majority of requests succeeded': (count) => count >= burstSize * 0.8,
    });

    return responses;
}

// Main stress test function
export default function() {
    concurrentConnections.add(__VU);  // Track VU count

    const rand = Math.random();

    if (rand < 0.40) {
        // 40% - Heavy event ingestion
        group('Stress Event Ingestion', () => {
            stressEventIngestion();
        });
    } else if (rand < 0.60) {
        // 20% - Complex queries
        group('Stress Queries', () => {
            stressQueryExecution();
        });
    } else if (rand < 0.75) {
        // 15% - Alert operations
        group('Stress Alerts', () => {
            stressAlertOperations();
        });
    } else if (rand < 0.85) {
        // 10% - Playbook stress
        group('Stress Playbooks', () => {
            stressPlaybookOperations();
        });
    } else {
        // 15% - Burst traffic
        group('Burst Traffic', () => {
            burstTraffic();
        });
    }

    // Minimal delay for maximum stress
    sleep(randomIntBetween(0, 1) / 10);
}

// Setup
export function setup() {
    console.log('Starting stress test...');
    console.log('WARNING: This test will push the system beyond normal limits');
    console.log(`Gateway URL: ${GATEWAY_URL}`);

    // Initial health check
    const healthResponse = http.get(`${GATEWAY_URL}/health`);
    if (healthResponse.status !== 200) {
        console.warn('Gateway not healthy at start - proceed with caution');
    }

    return {
        startTime: new Date().toISOString(),
        initialHealth: healthResponse.status === 200
    };
}

// Teardown
export function teardown(data) {
    console.log('Stress test completed');
    console.log(`Test started at: ${data.startTime}`);
    console.log(`Test ended at: ${new Date().toISOString()}`);

    // Final health check
    const healthResponse = http.get(`${GATEWAY_URL}/health`);
    if (healthResponse.status !== 200) {
        console.warn('Gateway not healthy after stress test - system may need recovery');
    } else {
        console.log('System recovered successfully');
    }
}

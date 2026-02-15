/**
 * K6 Performance Test for SIEM-SOAR Event Ingestion
 *
 * Tests the event ingestion pipeline for achieving 30K EPS target.
 *
 * Run: k6 run ingestion_test.js
 * Run with options: k6 run --vus 100 --duration 5m ingestion_test.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend, Gauge } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
const eventsIngested = new Counter('events_ingested');
const eventsPerSecond = new Gauge('events_per_second');
const ingestionLatency = new Trend('ingestion_latency', true);
const successRate = new Rate('success_rate');
const batchSize = new Trend('batch_size');

// Test configuration
export const options = {
    scenarios: {
        // Constant rate test - maintain steady EPS
        constant_rate: {
            executor: 'constant-arrival-rate',
            rate: 1000, // 1000 iterations per timeUnit
            timeUnit: '1s', // per second
            duration: '5m',
            preAllocatedVUs: 50,
            maxVUs: 200,
        },
        // Ramping test - increase to peak load
        ramping: {
            executor: 'ramping-arrival-rate',
            startRate: 100,
            timeUnit: '1s',
            stages: [
                { duration: '1m', target: 1000 },   // Ramp to 1K EPS
                { duration: '2m', target: 5000 },   // Ramp to 5K EPS
                { duration: '2m', target: 10000 },  // Ramp to 10K EPS
                { duration: '3m', target: 30000 },  // Ramp to 30K EPS (target)
                { duration: '5m', target: 30000 },  // Sustain 30K EPS
                { duration: '2m', target: 1000 },   // Cool down
            ],
            preAllocatedVUs: 100,
            maxVUs: 500,
        },
        // Spike test - sudden traffic spike
        spike: {
            executor: 'ramping-arrival-rate',
            startTime: '10m', // Start after ramping test
            startRate: 1000,
            timeUnit: '1s',
            stages: [
                { duration: '30s', target: 50000 }, // Sudden spike to 50K EPS
                { duration: '2m', target: 50000 },  // Sustain spike
                { duration: '30s', target: 1000 },  // Return to normal
            ],
            preAllocatedVUs: 200,
            maxVUs: 1000,
        },
    },
    thresholds: {
        'http_req_duration': ['p(95)<500', 'p(99)<1000'], // 95th < 500ms, 99th < 1s
        'http_req_failed': ['rate<0.01'], // Less than 1% failure
        'success_rate': ['rate>0.99'], // 99%+ success
        'ingestion_latency': ['p(95)<200', 'p(99)<500'], // 95th < 200ms
    },
};

// Environment configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE) || 100;

// Event types and severities
const EVENT_TYPES = [
    'PROCESS_LAUNCH',
    'NETWORK_CONNECTION',
    'FILE_CREATION',
    'FILE_MODIFICATION',
    'REGISTRY_MODIFICATION',
    'USER_LOGIN',
    'USER_LOGOUT',
    'SERVICE_START',
    'DNS_QUERY',
    'AUTHENTICATION_FAILURE',
];

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const PROCESS_NAMES = [
    'cmd.exe', 'powershell.exe', 'python.exe', 'bash',
    'java.exe', 'node.exe', 'chrome.exe', 'svchost.exe',
];

/**
 * Generate a random security event.
 */
function generateEvent() {
    const timestamp = new Date().toISOString();
    const eventType = EVENT_TYPES[randomIntBetween(0, EVENT_TYPES.length - 1)];
    const severity = SEVERITIES[randomIntBetween(0, SEVERITIES.length - 1)];

    return {
        event_id: `evt-${randomString(16)}`,
        timestamp: timestamp,
        event_type: eventType,
        severity: severity,
        source: {
            ip: `192.168.${randomIntBetween(1, 254)}.${randomIntBetween(1, 254)}`,
            hostname: `host-${randomIntBetween(1, 10000).toString().padStart(5, '0')}`,
            user: `user${randomIntBetween(1, 1000)}`,
            mac: `00:${randomIntBetween(10, 99)}:${randomIntBetween(10, 99)}:${randomIntBetween(10, 99)}:${randomIntBetween(10, 99)}:${randomIntBetween(10, 99)}`,
        },
        destination: {
            ip: `10.0.${randomIntBetween(1, 254)}.${randomIntBetween(1, 254)}`,
            port: [22, 80, 443, 445, 3389, 8080, 8443][randomIntBetween(0, 6)],
            hostname: `server-${randomIntBetween(1, 100)}`,
        },
        process: {
            name: PROCESS_NAMES[randomIntBetween(0, PROCESS_NAMES.length - 1)],
            pid: randomIntBetween(1000, 65000),
            command_line: randomString(100),
            hash: {
                md5: randomString(32),
                sha256: randomString(64),
            },
        },
        file: {
            path: `/home/user${randomIntBetween(1, 100)}/file${randomIntBetween(1, 1000)}.txt`,
            size: randomIntBetween(100, 10000000),
        },
        network: {
            bytes_sent: randomIntBetween(100, 1000000),
            bytes_received: randomIntBetween(100, 1000000),
            protocol: ['TCP', 'UDP', 'ICMP'][randomIntBetween(0, 2)],
        },
        metadata: {
            source: 'k6-test',
            raw_log: randomString(200),
        },
    };
}

/**
 * Generate a batch of events.
 */
function generateBatch(size) {
    const events = [];
    for (let i = 0; i < size; i++) {
        events.push(generateEvent());
    }
    return events;
}

/**
 * Main test function - executed by each VU.
 */
export default function() {
    group('Event Ingestion', function() {
        // Single event ingestion
        group('Single Event', function() {
            const event = generateEvent();
            const startTime = Date.now();

            const response = http.post(
                `${BASE_URL}/api/v1/events`,
                JSON.stringify(event),
                {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    tags: { name: 'single_event' },
                }
            );

            const latency = Date.now() - startTime;
            ingestionLatency.add(latency);

            const success = check(response, {
                'status is 200 or 202': (r) => r.status === 200 || r.status === 202,
                'response time < 500ms': (r) => r.timings.duration < 500,
            });

            if (success) {
                eventsIngested.add(1);
                successRate.add(1);
            } else {
                successRate.add(0);
            }
        });

        // Batch event ingestion
        group('Batch Events', function() {
            const size = randomIntBetween(50, 200);
            const events = generateBatch(size);
            batchSize.add(size);

            const startTime = Date.now();

            const response = http.post(
                `${BASE_URL}/api/v1/events/batch`,
                JSON.stringify({ events: events }),
                {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    tags: { name: 'batch_events' },
                }
            );

            const latency = Date.now() - startTime;
            ingestionLatency.add(latency);

            const success = check(response, {
                'status is 200 or 202': (r) => r.status === 200 || r.status === 202,
                'response time < 2000ms': (r) => r.timings.duration < 2000,
            });

            if (success) {
                eventsIngested.add(size);
                successRate.add(1);
            } else {
                successRate.add(0);
            }
        });
    });

    // Small sleep to prevent overwhelming
    sleep(0.01);
}

/**
 * Setup function - runs once before the test.
 */
export function setup() {
    console.log('Starting SIEM-SOAR Ingestion Performance Test');
    console.log(`Target: ${BASE_URL}`);
    console.log(`Batch size: ${BATCH_SIZE}`);

    // Health check
    const healthResponse = http.get(`${BASE_URL}/health`);
    if (healthResponse.status !== 200) {
        console.error('Service is not healthy!');
    }

    return { startTime: Date.now() };
}

/**
 * Teardown function - runs once after the test.
 */
export function teardown(data) {
    const duration = (Date.now() - data.startTime) / 1000;
    console.log(`Test completed in ${duration.toFixed(2)} seconds`);
}

/**
 * Custom summary handler.
 */
export function handleSummary(data) {
    const totalEvents = data.metrics.events_ingested?.values?.count || 0;
    const testDuration = data.state.testRunDurationMs / 1000;
    const avgEPS = totalEvents / testDuration;

    const summary = {
        test_name: 'SIEM-SOAR Ingestion Test',
        timestamp: new Date().toISOString(),
        duration_seconds: testDuration,
        total_events: totalEvents,
        average_eps: avgEPS,
        target_eps: 30000,
        target_achieved: avgEPS >= 30000,
        p95_latency_ms: data.metrics.ingestion_latency?.values?.['p(95)'] || 0,
        p99_latency_ms: data.metrics.ingestion_latency?.values?.['p(99)'] || 0,
        success_rate: (data.metrics.success_rate?.values?.rate || 0) * 100,
        http_req_duration_p95: data.metrics.http_req_duration?.values?.['p(95)'] || 0,
        http_req_failed_rate: (data.metrics.http_req_failed?.values?.rate || 0) * 100,
    };

    console.log('\n========== TEST SUMMARY ==========');
    console.log(`Total Events Ingested: ${totalEvents.toLocaleString()}`);
    console.log(`Average EPS: ${avgEPS.toFixed(2)}`);
    console.log(`Target (30K EPS): ${summary.target_achieved ? 'ACHIEVED ✓' : 'NOT ACHIEVED ✗'}`);
    console.log(`P95 Latency: ${summary.p95_latency_ms.toFixed(2)}ms`);
    console.log(`P99 Latency: ${summary.p99_latency_ms.toFixed(2)}ms`);
    console.log(`Success Rate: ${summary.success_rate.toFixed(2)}%`);
    console.log('==================================\n');

    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }),
        'summary.json': JSON.stringify(summary, null, 2),
    };
}

/**
 * Text summary helper.
 */
function textSummary(data, options) {
    let output = '\n';

    // Add custom metrics
    output += '     events_ingested.......: ' +
        (data.metrics.events_ingested?.values?.count || 0).toLocaleString() + '\n';
    output += '     ingestion_latency.....: avg=' +
        (data.metrics.ingestion_latency?.values?.avg || 0).toFixed(2) + 'ms ' +
        'p(95)=' + (data.metrics.ingestion_latency?.values?.['p(95)'] || 0).toFixed(2) + 'ms\n';
    output += '     success_rate..........: ' +
        ((data.metrics.success_rate?.values?.rate || 0) * 100).toFixed(2) + '%\n';

    return output;
}

/**
 * K6 Load Test for SIEM/SOAR Platform
 *
 * This test simulates normal production load to verify system performance.
 * Target: 100,000 EPS (Events Per Second) for enterprise deployment.
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Counter, Trend } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const eventsIngested = new Counter('events_ingested');
const alertsGenerated = new Counter('alerts_generated');
const queryLatency = new Trend('query_latency');
const eventIngestionLatency = new Trend('event_ingestion_latency');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const GATEWAY_URL = __ENV.GATEWAY_URL || 'http://localhost:8080';
const COLLECTOR_URL = __ENV.COLLECTOR_URL || 'http://localhost:8086';

// Test configuration options
export const options = {
    scenarios: {
        // Ramp up to target load
        load_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '2m', target: 50 },   // Ramp up to 50 VUs
                { duration: '5m', target: 100 },  // Ramp up to 100 VUs
                { duration: '10m', target: 100 }, // Maintain 100 VUs
                { duration: '5m', target: 200 },  // Ramp up to 200 VUs
                { duration: '10m', target: 200 }, // Maintain 200 VUs
                { duration: '3m', target: 0 },    // Ramp down
            ],
            gracefulRampDown: '30s',
        },
    },
    thresholds: {
        'http_req_duration': ['p(95)<500', 'p(99)<1000'],  // 95th percentile < 500ms
        'http_req_failed': ['rate<0.01'],                   // Error rate < 1%
        'errors': ['rate<0.01'],                            // Custom error rate < 1%
        'event_ingestion_latency': ['p(95)<100'],           // Event ingestion < 100ms
        'query_latency': ['p(95)<1000'],                    // Query latency < 1s
    },
};

// Generate sample security event
function generateSecurityEvent() {
    const eventTypes = ['auth_failure', 'auth_success', 'connection', 'process_create', 'file_access'];
    const severities = ['low', 'medium', 'high', 'critical'];
    const services = ['sshd', 'httpd', 'mysql', 'postgresql', 'nginx'];

    return {
        timestamp: new Date().toISOString(),
        event_id: randomString(32),
        event_type: eventTypes[randomIntBetween(0, eventTypes.length - 1)],
        severity: severities[randomIntBetween(0, severities.length - 1)],
        source: {
            ip: `192.168.${randomIntBetween(1, 254)}.${randomIntBetween(1, 254)}`,
            port: randomIntBetween(1024, 65535),
            hostname: `host-${randomString(8)}`
        },
        destination: {
            ip: `10.0.${randomIntBetween(0, 255)}.${randomIntBetween(1, 254)}`,
            port: randomIntBetween(1, 1024),
            hostname: `server-${randomString(6)}`
        },
        user: {
            name: `user${randomIntBetween(1, 1000)}`,
            domain: 'CORP'
        },
        service: services[randomIntBetween(0, services.length - 1)],
        message: `Test event ${randomString(16)}`,
        metadata: {
            collector_id: `collector-${randomIntBetween(1, 10)}`,
            original_source: 'syslog'
        }
    };
}

// Generate batch of events
function generateEventBatch(size) {
    const events = [];
    for (let i = 0; i < size; i++) {
        events.push(generateSecurityEvent());
    }
    return events;
}

// Test event ingestion
function testEventIngestion() {
    const batchSize = randomIntBetween(10, 100);
    const events = generateEventBatch(batchSize);

    const startTime = Date.now();
    const response = http.post(
        `${COLLECTOR_URL}/api/v1/events/batch`,
        JSON.stringify({ events: events }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'event_ingestion' }
        }
    );

    const latency = Date.now() - startTime;
    eventIngestionLatency.add(latency);

    const success = check(response, {
        'event ingestion status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    if (success) {
        eventsIngested.add(batchSize);
    } else {
        errorRate.add(1);
    }

    return response;
}

// Test alert retrieval
function testAlertRetrieval() {
    const response = http.get(
        `${GATEWAY_URL}/api/v1/alerts?limit=50`,
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'alert_retrieval' }
        }
    );

    check(response, {
        'alert retrieval status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    return response;
}

// Test query execution
function testQueryExecution() {
    const queries = [
        "SELECT count(*) FROM events WHERE timestamp >= now() - INTERVAL 1 HOUR",
        "SELECT event_type, count(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC LIMIT 10",
        "SELECT src_ip, count(*) FROM events WHERE event_type = 'auth_failure' GROUP BY src_ip ORDER BY count(*) DESC LIMIT 10",
        "SELECT toStartOfMinute(timestamp) as minute, count(*) FROM events GROUP BY minute ORDER BY minute DESC LIMIT 60"
    ];

    const query = queries[randomIntBetween(0, queries.length - 1)];

    const startTime = Date.now();
    const response = http.post(
        `${GATEWAY_URL}/api/v1/query`,
        JSON.stringify({
            query: query,
            start_time: new Date(Date.now() - 3600000).toISOString(),
            end_time: new Date().toISOString()
        }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'query_execution' }
        }
    );

    const latency = Date.now() - startTime;
    queryLatency.add(latency);

    check(response, {
        'query status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    return response;
}

// Test detection rules
function testDetectionRules() {
    const response = http.get(
        `${GATEWAY_URL}/api/v1/rules?enabled=true`,
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'detection_rules' }
        }
    );

    check(response, {
        'rules retrieval status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    return response;
}

// Test playbook listing
function testPlaybooks() {
    const response = http.get(
        `${GATEWAY_URL}/api/v1/playbooks`,
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'playbooks' }
        }
    );

    check(response, {
        'playbooks retrieval status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    return response;
}

// Test case management
function testCaseManagement() {
    const response = http.get(
        `${GATEWAY_URL}/api/v1/cases?status=investigating&limit=20`,
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'case_management' }
        }
    );

    check(response, {
        'cases retrieval status is 2xx': (r) => r.status >= 200 && r.status < 300,
    });

    return response;
}

// Health check
function testHealthCheck() {
    const response = http.get(
        `${GATEWAY_URL}/health`,
        { tags: { name: 'health_check' } }
    );

    check(response, {
        'health check status is 200': (r) => r.status === 200,
        'health status is healthy': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.status === 'healthy';
            } catch {
                return false;
            }
        }
    });

    return response;
}

// Main test function
export default function() {
    group('Health Check', () => {
        testHealthCheck();
    });

    // Weight different operations based on realistic usage patterns
    const rand = Math.random();

    if (rand < 0.60) {
        // 60% - Event ingestion (highest volume)
        group('Event Ingestion', () => {
            testEventIngestion();
        });
    } else if (rand < 0.80) {
        // 20% - Alert and query operations
        group('Alerts and Queries', () => {
            testAlertRetrieval();
            testQueryExecution();
        });
    } else if (rand < 0.90) {
        // 10% - Detection rules
        group('Detection Rules', () => {
            testDetectionRules();
        });
    } else if (rand < 0.95) {
        // 5% - Playbooks
        group('Playbooks', () => {
            testPlaybooks();
        });
    } else {
        // 5% - Case management
        group('Case Management', () => {
            testCaseManagement();
        });
    }

    // Small delay between iterations
    sleep(randomIntBetween(1, 3) / 10);  // 0.1 - 0.3 seconds
}

// Setup function - runs once before test
export function setup() {
    console.log('Starting load test...');
    console.log(`Gateway URL: ${GATEWAY_URL}`);
    console.log(`Collector URL: ${COLLECTOR_URL}`);

    // Verify services are available
    const healthResponse = http.get(`${GATEWAY_URL}/health`);
    if (healthResponse.status !== 200) {
        console.warn('Gateway health check failed - some tests may fail');
    }

    return { startTime: new Date().toISOString() };
}

// Teardown function - runs once after test
export function teardown(data) {
    console.log('Load test completed');
    console.log(`Test started at: ${data.startTime}`);
    console.log(`Test ended at: ${new Date().toISOString()}`);
}

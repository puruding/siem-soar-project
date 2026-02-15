/**
 * K6 Spike Test for SIEM/SOAR Platform
 *
 * This test simulates sudden traffic spikes to verify system behavior
 * under rapid load changes, similar to DDoS attacks or security incidents
 * that generate massive alert volumes.
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Counter, Trend, Gauge } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics
const errorRate = new Rate('errors');
const recoveryTime = new Trend('recovery_time');
const spikeHandled = new Counter('spikes_handled');
const requestsDuringSpike = new Counter('requests_during_spike');

// Configuration
const GATEWAY_URL = __ENV.GATEWAY_URL || 'http://localhost:8080';
const COLLECTOR_URL = __ENV.COLLECTOR_URL || 'http://localhost:8086';

// Spike test configuration
export const options = {
    scenarios: {
        spike_test: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                // Normal load baseline
                { duration: '2m', target: 50 },

                // SPIKE 1: Sudden surge
                { duration: '10s', target: 500 },  // 10x increase in 10 seconds
                { duration: '1m', target: 500 },   // Maintain spike
                { duration: '10s', target: 50 },   // Quick drop

                // Recovery period
                { duration: '2m', target: 50 },

                // SPIKE 2: Even larger spike
                { duration: '5s', target: 800 },   // 16x increase in 5 seconds
                { duration: '30s', target: 800 },  // Short maintenance
                { duration: '10s', target: 50 },   // Drop

                // Recovery period
                { duration: '2m', target: 50 },

                // SPIKE 3: Extreme spike
                { duration: '5s', target: 1200 },  // 24x increase
                { duration: '15s', target: 1200 }, // Very short spike
                { duration: '5s', target: 50 },    // Immediate drop

                // Final recovery observation
                { duration: '3m', target: 50 },
                { duration: '30s', target: 0 },
            ],
            gracefulRampDown: '10s',
        },
    },
    thresholds: {
        // Focus on recovery and spike handling
        'http_req_duration': ['p(95)<3000'],  // Allow slower during spikes
        'http_req_failed': ['rate<0.20'],     // Allow more errors during extreme spikes
        'errors': ['rate<0.25'],
    },
};

// Generate alert surge (simulating security incident)
function generateAlertSurge() {
    const alerts = [];
    const count = randomIntBetween(50, 200);

    const alertTypes = [
        'DDoS Attack',
        'Brute Force',
        'Malware Detected',
        'Data Exfiltration',
        'Suspicious Login',
        'Port Scan',
        'Ransomware Activity'
    ];

    for (let i = 0; i < count; i++) {
        alerts.push({
            id: randomString(32),
            type: alertTypes[randomIntBetween(0, alertTypes.length - 1)],
            severity: 'critical',
            timestamp: new Date().toISOString(),
            source_ip: `203.0.113.${randomIntBetween(1, 254)}`,
            target_ip: `10.0.${randomIntBetween(0, 255)}.${randomIntBetween(1, 254)}`,
            message: `Spike test alert ${randomString(16)}`
        });
    }

    return alerts;
}

// Generate event flood
function generateEventFlood() {
    const events = [];
    const count = randomIntBetween(500, 2000);

    for (let i = 0; i < count; i++) {
        events.push({
            timestamp: new Date().toISOString(),
            event_id: randomString(32),
            event_type: 'security_event',
            source: { ip: `192.168.${randomIntBetween(1, 254)}.${randomIntBetween(1, 254)}` },
            destination: { ip: `10.0.${randomIntBetween(0, 255)}.${randomIntBetween(1, 254)}` },
            message: randomString(100)
        });
    }

    return events;
}

// Spike traffic pattern - many concurrent requests
function spikeEventIngestion() {
    const events = generateEventFlood();

    const startTime = Date.now();
    const response = http.post(
        `${COLLECTOR_URL}/api/v1/events/batch`,
        JSON.stringify({ events: events }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'spike_event_ingestion' },
            timeout: '120s'
        }
    );
    const duration = Date.now() - startTime;

    requestsDuringSpike.add(1);

    const success = check(response, {
        'spike event ingestion accepted': (r) => r.status >= 200 && r.status < 300,
    });

    if (!success) {
        errorRate.add(1);
    } else {
        spikeHandled.add(1);
    }

    return { response, duration };
}

// Concurrent API requests during spike
function spikeAPIRequests() {
    const endpoints = [
        `${GATEWAY_URL}/api/v1/alerts?limit=50`,
        `${GATEWAY_URL}/api/v1/rules`,
        `${GATEWAY_URL}/api/v1/playbooks`,
        `${GATEWAY_URL}/api/v1/cases?limit=20`,
        `${GATEWAY_URL}/health`
    ];

    const requests = endpoints.map(url => ['GET', url, null, { tags: { name: 'spike_api_request' } }]);

    const startTime = Date.now();
    const responses = http.batch(requests);
    const duration = Date.now() - startTime;

    let successCount = 0;
    responses.forEach(r => {
        requestsDuringSpike.add(1);
        if (r.status >= 200 && r.status < 300 || r.status === 404) {
            successCount++;
        } else {
            errorRate.add(1);
        }
    });

    check(successCount, {
        'spike: API requests handled': (count) => count >= endpoints.length * 0.5,
    });

    return { responses, duration };
}

// Query spike - many concurrent queries
function spikeQueryRequests() {
    const query = `
        SELECT
            src_ip,
            event_type,
            count(*) as cnt
        FROM events
        WHERE timestamp >= now() - INTERVAL 5 MINUTE
        GROUP BY src_ip, event_type
        ORDER BY cnt DESC
        LIMIT 100
    `;

    const response = http.post(
        `${GATEWAY_URL}/api/v1/query`,
        JSON.stringify({
            query: query,
            start_time: new Date(Date.now() - 300000).toISOString(),
            end_time: new Date().toISOString()
        }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'spike_query' },
            timeout: '60s'
        }
    );

    requestsDuringSpike.add(1);

    check(response, {
        'spike query handled': (r) => r.status >= 200 && r.status < 300 || r.status === 404,
    });

    if (response.status >= 500) {
        errorRate.add(1);
    }

    return response;
}

// Playbook trigger spike
function spikePlaybookTrigger() {
    const response = http.post(
        `${GATEWAY_URL}/api/v1/playbooks/incident-response/execute`,
        JSON.stringify({
            trigger_data: {
                alert_id: randomString(32),
                severity: 'critical',
                incident_type: 'spike_test'
            }
        }),
        {
            headers: { 'Content-Type': 'application/json' },
            tags: { name: 'spike_playbook_trigger' }
        }
    );

    requestsDuringSpike.add(1);

    check(response, {
        'spike playbook trigger handled': (r) => [200, 202, 404, 429].includes(r.status),
    });

    return response;
}

// Health check during spike
function healthCheckDuringSpike() {
    const response = http.get(
        `${GATEWAY_URL}/health`,
        { tags: { name: 'spike_health_check' } }
    );

    const healthy = check(response, {
        'service remains healthy during spike': (r) => r.status === 200,
    });

    if (!healthy) {
        console.warn('Service health degraded during spike');
    }

    return response;
}

// Measure recovery time
function measureRecoveryTime() {
    const maxAttempts = 30;
    const checkInterval = 2000;  // 2 seconds
    let recoveredAt = null;

    for (let i = 0; i < maxAttempts; i++) {
        const response = http.get(`${GATEWAY_URL}/health`);

        if (response.status === 200 && response.timings.duration < 500) {
            recoveredAt = i * checkInterval;
            break;
        }

        sleep(checkInterval / 1000);
    }

    if (recoveredAt !== null) {
        recoveryTime.add(recoveredAt);
        console.log(`System recovered in ${recoveredAt}ms`);
    } else {
        console.warn('System did not recover within expected time');
    }

    return recoveredAt;
}

// Main spike test function
export default function() {
    // Mix of operations during spike
    const rand = Math.random();

    group('Spike Operations', () => {
        if (rand < 0.35) {
            // 35% - Event flood
            spikeEventIngestion();
        } else if (rand < 0.55) {
            // 20% - API requests
            spikeAPIRequests();
        } else if (rand < 0.70) {
            // 15% - Query spike
            spikeQueryRequests();
        } else if (rand < 0.80) {
            // 10% - Playbook triggers
            spikePlaybookTrigger();
        } else {
            // 20% - Health monitoring
            healthCheckDuringSpike();
        }
    });

    // Very short delay during spikes
    sleep(randomIntBetween(0, 50) / 1000);
}

// Setup
export function setup() {
    console.log('Starting spike test...');
    console.log('WARNING: This test simulates extreme traffic spikes');
    console.log(`Gateway URL: ${GATEWAY_URL}`);
    console.log(`Collector URL: ${COLLECTOR_URL}`);

    // Baseline health check
    const healthResponse = http.get(`${GATEWAY_URL}/health`);
    const baselineHealthy = healthResponse.status === 200;
    const baselineLatency = healthResponse.timings.duration;

    console.log(`Baseline health: ${baselineHealthy}, latency: ${baselineLatency}ms`);

    return {
        startTime: new Date().toISOString(),
        baselineHealthy,
        baselineLatency
    };
}

// Teardown
export function teardown(data) {
    console.log('Spike test completed');
    console.log(`Test started at: ${data.startTime}`);
    console.log(`Test ended at: ${new Date().toISOString()}`);
    console.log(`Baseline latency was: ${data.baselineLatency}ms`);

    // Final recovery check
    console.log('Checking system recovery...');
    const finalRecoveryTime = measureRecoveryTime();

    if (finalRecoveryTime !== null) {
        console.log(`Final recovery time: ${finalRecoveryTime}ms`);
    }

    // Compare to baseline
    const healthResponse = http.get(`${GATEWAY_URL}/health`);
    const finalLatency = healthResponse.timings.duration;
    console.log(`Final latency: ${finalLatency}ms (baseline was ${data.baselineLatency}ms)`);

    if (finalLatency > data.baselineLatency * 2) {
        console.warn('System latency is still elevated after spike test');
    }
}

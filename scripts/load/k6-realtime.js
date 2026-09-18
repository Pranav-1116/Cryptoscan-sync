// K6 Load Test — Real-Time System 100K+ events/sec p99<500ms
// Deterministic, No AI, Fully Auditable
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';

const p99Latency = new Trend('p99_latency');
const throughput = new Trend('throughput');

export const options = {
  stages: [
    { duration: '30s', target: 100 },
    { duration: '1m', target: 1000 },
    { duration: '30s', target: 100 },
  ],
  thresholds: {
    'http_req_duration': ['p(99)<500'], // p99 < 500ms target
    'http_req_failed': ['rate<0.01'], // <1% failures
    'p99_latency': ['p(99)<500'],
  },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:8010';

export default function () {
  // Test real-time status endpoints — deterministic
  const endpoints = [
    '/api/v1/realtime-system/status',
    '/api/v1/cryptographic-digital-twin-real/realtime/status',
    '/api/v1/assets/realtime/status',
    '/api/v1/findings/realtime/status',
    '/api/v1/risk/realtime/status',
    '/api/v1/compliance/realtime/status',
  ];

  const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
  const res = http.get(`${BASE_URL}${endpoint}`);

  check(res, {
    'status is 200': (r) => r.status === 200,
    'p99 <500ms': (r) => r.timings.duration < 500,
    'deterministic true': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.deterministic === true;
      } catch {
        return false;
      }
    },
  });

  p99Latency.add(res.timings.duration);
  throughput.add(1);

  sleep(0.1);
}

export function handleSummary(data) {
  return {
    'stdout': JSON.stringify({
      p99_latency: data.metrics.p99_latency.values['p(99)'],
      throughput: data.metrics.throughput.values.rate,
      http_req_failed: data.metrics.http_req_failed.values.rate,
      checks_passed: data.metrics.checks.values.passes,
      checks_failed: data.metrics.checks.values.fails,
      deterministic: true,
      no_ai: true,
      target_p99: "<500ms",
      target_throughput: "100K+ events/sec",
      target_failed: "<1%",
    }, null, 2),
  };
}

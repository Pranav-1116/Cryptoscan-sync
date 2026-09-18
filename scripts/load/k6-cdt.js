// K6 Load Test — CDT Real Engine Simulation
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '1m', target: 100 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    'http_req_duration': ['p(99)<1000'],
    'http_req_failed': ['rate<0.05'],
  },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:8010';

export default function () {
  // Test CDT simulation — deterministic
  const payload = JSON.stringify({
    scenario_type: "MIGRATION_SIMULATION",
    name: `Load Test RSA-2048 to ML-KEM-768 ${__VU}-${__ITER}`,
    scope: { system_ids: ["sys-payment-api", "sys-auth-service"] },
    changes: [{
      change_type: "ALGORITHM_SWAP",
      target_type: "System",
      from_value: "RSA-2048",
      to_value: "ML-KEM-768",
      properties: { hybrid_mode: "ML-KEM-768+X25519" }
    }],
    constraints: { max_downtime: "4h", team_size: 3, budget: 100000 },
    assumptions: { performance_overhead: "15%", testing_duration: "2 weeks" }
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token',
    },
  };

  const res = http.post(`${BASE_URL}/api/v1/cryptographic-digital-twin-real/simulate`, payload, params);

  check(res, {
    'status is 200 or 401 (auth)': (r) => r.status === 200 || r.status === 401,
    'simulation has impact': (r) => {
      if (r.status !== 200) return true;
      try {
        const body = JSON.parse(r.body);
        return body.impact && body.impact.direct_systems !== undefined;
      } catch {
        return false;
      }
    },
    'deterministic true': (r) => {
      if (r.status !== 200) return true;
      try {
        const body = JSON.parse(r.body);
        return body.deterministic === true;
      } catch {
        return false;
      }
    },
  });

  sleep(0.5);
}

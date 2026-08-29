# Vendor crypto discovery

Four discovery methods feed `vendor_crypto_inventory`:

1. **API endpoint scan** (`POST /vendors/{id}/api-scan`) — live TLS probe
2. Questionnaire (`GET/POST /vendors/{id}/questionnaire`)
3. CycloneDX CBOM import (`POST /vendors/{id}/cbom`)
4. Documentation extraction (`POST /vendors/{id}/docs`)

`GET /vendor-risks` rolls those observations into a 0–100 score
(crypto strength + PQC posture + data sensitivity + transparency).

## API endpoint scan (method 1)

```bash
curl -s -X POST "$API/api/v1/vendors/$VENDOR_ID/api-scan" \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"endpoint": "api.stripe.com:443", "scan_ciphers": true}'
```

The scan probes the vendor's endpoint live and stores **what was actually observed on
the wire**, not what the vendor claims:

- the negotiated protocol (`TLS1.3` …) **and** the cipher suite, as two inventory rows —
  the registry treats TLS 1.0/1.1 as disallowed even when the cipher itself parses as
  allowed, so a legacy endpoint cannot hide behind an AES cipher name;
- key size and mode when the cipher reveals them, key exchange as `key_management`;
- `discovery_method: "API_SCAN"`, `confidence` from the probe, `verified_at` set —
  observed directly, unlike self-reported questionnaire answers.

Unreachable endpoints are reported honestly (`status: "DNS_FAILED"`,
`stored: false`) and store nothing — a dead probe is a fact about reachability,
 not about the vendor's crypto.

## Reading the risk

Each vendor gets `GET /vendors/{id}/risk`: score, category (LOW / MEDIUM / HIGH),
the worst algorithm status found, and the full inventory with its discovery method.
Evidence wins over paperwork: if a questionnaire claims PQC readiness but the
inventory contains Shor-vulnerable crypto, the discrepancy is reported and scored.

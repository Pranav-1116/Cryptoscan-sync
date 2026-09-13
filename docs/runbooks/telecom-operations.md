# Telecom realtime scanner — operations runbook

How to operate the telecom crypto scanner on a real carrier estate:
registry, scan modes, ingest, packs, metrics, and what to do when the
event feed lights up. The scanner classifies the cryptographic posture of
3GPP network functions (5G SBA, EPC, IMS, signaling, NDS/IP) per
3GPP TS 33.210 / TS 33.501 and NIST SP 800-52r2 / IR 8547.

## 1. Concepts

| Object | Meaning | Where it lives |
|---|---|---|
| **Carrier** | One operator network: `code`, name, ISO country, **PLMN** (ITU-T E.212 `MCC-MNC`), optional `legal_entity` (group view) | registry file |
| **NF target** | One network function endpoint: `nf_id`, `nf_type` (amf, smf, sepp, ipsecgw, …), `endpoint` host:port, `environment` | registry file |
| **Roaming partner** | An inter-PLMN agreement (`partner_plmn`), optionally mapped to the SEPP that protects it | registry file |
| **Verdict** | One NF's classification from the latest pass: status, severity, findings, `crypto_inventory`, `fingerprint` | snapshot (memory + `data/`) |

Registry path resolution: `CRYPTOSCAN_TELECOM_REGISTRY` env var →
`<CRYPTOSCAN_ROOT>/config/telecom_registry.json` → writable fallback under
`CRYPTOSCAN_HOME`. The snapshot mirrors to
`CRYPTOSCAN_SNAPSHOT_DIR` (default `data/`), so restarts keep serving the
last posture.

## 1b. Continuous monitoring (24/7)

On-demand `POST /telecom/scan` passes are point-in-time. For continuous
posture, register a TELECOM monitor target and let the daemon re-probe on
interval (default 15 min):

```bash
curl -X POST $API/api/v1/monitor/targets -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"name":"carrier estate","target_type":"TELECOM","config":{}}'
```

Each pass runs the same probe/classify engine, mirrors the snapshot (so
`/telecom/posture` and the exit report stay current — the API picks up
daemon-written snapshots by file mtime, no restart), and raises
`monitor.scan_degraded` / `monitor.alert` events (SSE) when a NF turns
critical. Scope to one carrier with `{"carrier":"de-telekom"}`.

## 2. Bring-up

```bash
# 1) register the estate (API is telecom.manage-gated: superadmin/ciso/security_analyst)
curl -X POST $API/api/v1/telecom/carriers -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"code":"de-telekom","name":"Deutsche Telekom","country":"de","plmn":"262-01","legal_entity":"dt-group"}'
curl -X POST $API/api/v1/telecom/targets -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"nf_id":"amf-prod-01","nf_type":"amf","endpoint":"sba.corp.example:443","carrier_code":"de-telekom"}'

# 2) first pass (bounded: max 64 targets per on-demand scan)
curl -X POST $API/api/v1/telecom/scan -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"timeout": 4.0}'

# 3) periodic mode: enable in the API env, restart
CRYPTOSCAN_LIVE_TELECOM=1            # live-scan loop picks up the registry-driven spec
CRYPTOSCAN_LIVE_INTERVAL=900         # seconds between full live passes
```

Design rule: **the scanner only probes targets the operator registered.**
No discovery sweeps, no scanning of unregistered networks — on a carrier
estate that boundary is the difference between monitoring and an RFC.

## 3. Scan modes

- **Periodic live pass** (`CRYPTOSCAN_LIVE_TELECOM=1`): the runner invokes
  `python -m telecom_scanner.main --json --state data/telecom_state.json`
  on the live loop; the state file drives the realtime diff across
  restarts. Events publish as `telecom.event` on the bus (SSE + Redis
  federation in multi-replica setups).
- **On-demand pass** (`POST /telecom/scan`, `scan.trigger` permission):
  bounded 64 targets, optional `only: [nf_id, …]`, returns the refreshed
  posture. Use for a spot check or right after registry changes.
- **Operator ingest** (`POST /telecom/ingest`, `telecom.ingest`): classify
  results you obtained inside the network — IKE/IPsec parameters, or a TLS
  probe of an NF that is not reachable from the scanner's vantage (NATed
  management planes). The scanner NEVER fakes what it did not observe:
  IPsec gateways without ingest read `IPSEC_UNKNOWN` (score 100 — unknown
  is neither pass nor fail).

## 4. Reading the verdicts

| Status | Meaning | Typical severity |
|---|---|---|
| `TLS_OK` | handshake completed; findings list carries the details | info → critical by findings |
| `NO_TLS` | endpoint refused TLS (`TLS_ERROR`/`STARTTLS_REFUSED`/`MTLS_REQUIRED`) | **critical** (TS 33.210) |
| `UNREACHABLE` | DNS/timeout/closed/connect error | critical on 5gc/roaming/epc planes, high elsewhere |
| `NOT_PROBED` | no probe result in this pass | info |
| `IPSEC_UNKNOWN` / `IPSEC_REVIEWED` | NDS/IP gateway without / with operator ingest | info / per findings |

Verdict rules worth knowing cold:

- An **unprotected SEPP** is named `sepp.roaming_unprotected` (critical,
  TS 33.501) — the international-roaming edge must be demonstrably TLS.
- `TLSv1`/`TLSv1.1` on any NF interface is **critical** (33.210 floor);
  TLS 1.2 draws an info-level migrate note (800-52r2 prefers 1.3).
- Expired certificate = critical; ≤7 days = high; ≤30 days = medium.
- Hybrid ML-KEM key exchange on SBI is recorded as `pqc.hybrid_kem`
  (info) — early-adopters surface in `pqc_kex` and the roaming matrix's
  `pqc_ready` flag.

## 5. When the feed lights up

`telecom.event` kinds on the bus and what the automation layer does:

| Event | Automation trigger | Playbook |
|---|---|---|
| `TELECOM_REACHABILITY_LOST` | `agent_offline` | `pb_telecom_nf_down` — re-probe, NOC alert, ticket, **gated failover** |
| `TELECOM_CERT_EXPIRING` | `certificate_expiring` | `pb_certificate_expiring` — owner ticket, gated rotation |
| `TELECOM_FINDINGS_CHANGED` (high/critical) | `drift_detected` | `pb_drift` — rescan, alert, ticket |
| `TELECOM_PQC_DROPPED` | `quantum_vulnerable_detected` | `pb_pqc` — rescan, CBOM refresh, migration queue, ticket, **gated approval** |
| `TELECOM_RECOVERED`, `TELECOM_PQC_READY`, `TELECOM_TARGET_ADDED`, info changes | — (None) | noise never wakes the engine |

Add operator rules under Automation (the telecom condition data carries
`nf_id`, `carrier_code`, `plane`, `environment`, so rules can target e.g.
`plane == "roaming"`).

## 6. Regulatory artifacts

- `GET /telecom/roadmap` — carrier-bucketed NIST IR 8547 migration plan
  (legacy → purge now, 112-bit → 2030, ≥128-bit → 2035).
- `GET /banking/group/roadmap?include_telecom=true` — the supervisory
  artifact with carrier families folded into group legal entities.
- `GET /telecom/pack?carrier=<code>&format=json|csv` — per-carrier NRA
  pack (the national-regulator artifact; other carriers' rows excluded).
- `GET /telecom/roaming` — partner matrix: protected / unprotected /
  `unknown` (an unprobed edge is never reported as protected).

## 7. Metrics & alerting

Prometheus (scrape `:8080/metrics`):

- `cryptoscan_telecom_targets_registered`
- `cryptoscan_telecom_targets_by_severity{severity=…}`
- `cryptoscan_telecom_targets_unreachable`
- `cryptoscan_telecom_scan_age_seconds` (-1 = never scanned; alert if
  > 2× your live interval — it means the loop stopped)

Suggested alert: `telecom_scan_age_seconds > 2 × interval` (scanner dead)
and `telecom_targets_by_severity{severity="critical"} > baseline`
(posture regression).

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| `/telecom/posture` says "No telecom scan yet" | registry empty or no pass yet — register targets, then `POST /telecom/scan` |
| All targets `UNREACHABLE` | scanner vantage has no route — expected from outside carrier NAT; use `/telecom/ingest` with in-network results |
| `IPSEC_UNKNOWN` won't go away | NDS/IP classification needs `/telecom/ingest` with IKE parameters (IKEv2, DH ≥ 14, AES-GCM) |
| Scan rejects with 413 "64-per-pass cap" | estate > 64 targets — rely on the periodic loop or run `only:` batches |
| 403 on registry writes | role lacks `telecom.manage` (superadmin/ciso/security_analyst) |
| Events not reaching SSE clients | bus works but nothing published — events fire on CHANGES; first pass is a quiet baseline (except already-critical findings) |

## 9. Boundaries (by design)

- Read-only probing of registered targets only; no sweeps.
- No key material anywhere — cryptographic metadata only.
- Unknown ≠ pass ≠ fail: unprobed surfaces are labeled as such, and the
  declared limits travel with every pack.

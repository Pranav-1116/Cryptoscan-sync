# 63_CONTINUOUS_CRYPTO_MONITORING_AUDIT.md
## ZELNX CryptoScan — Continuous Crypto Monitoring Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of continuous monitoring capabilities vs periodic scanning  
**Scope:** Complete monitoring pipeline — scheduled discovery, event-based discovery, cloud changes, certificate changes, dependency changes, network changes, configuration changes, crypto changes, drift, alerts

---

## EXECUTIVE SUMMARY

**Core Question:** *"Does ZELNX support continuous intelligence rather than periodic scanning?"*

**Answer:** **PARTIAL** — Has a monitor daemon with scheduled re-scans, but **lacks true event-driven continuous monitoring**, real-time change detection, and intelligent alerting.

| Monitoring Capability | Status | Score |
|----------------------|--------|-------|
| **Scheduled Discovery** | ✅ Yes | 8/10 |
| **Event-Based Discovery** | ❌ No | 1/10 |
| **Cloud Config Changes** | ⚠️ Periodic only | 3/10 |
| **Certificate Changes** | ✅ Monitored | 7/10 |
| **Dependency Changes** | ❌ No | 1/10 |
| **Network Changes** | ⚠️ Periodic only | 3/10 |
| **Configuration Changes** | ⚠️ Periodic only | 3/10 |
| **Crypto Changes** | ⚠️ Periodic only | 3/10 |
| **Drift Detection** | ✅ Periodic | 7/10 |
| **Real-Time Alerts** | ❌ Missing | 1/10 |
| **Event-Driven Re-analysis** | ❌ Missing | 1/10 |

**Overall: 3.3/10** — Scheduled scanning only, no true continuous monitoring

---

## 1. MONITORING ARCHITECTURE — CURRENT STATE

### 1.1 Monitor Daemon

**File:** `scripts/run_monitor.py` + `services/monitor/`

```python
# MonitorDaemon runs every MONITOR_TICK_SECONDS (default 30s)
# Checks watch-list targets:
# - Network targets (TLS probes)
# - Cloud accounts (config drift)
# - Repository scans (scheduled)
# - Container images (scheduled)
```

### 1.2 Monitor Configuration

**Environment Variables:**
```bash
MONITOR_TICK_SECONDS=30
MONITOR_LEASE_TTL_SECONDS=60
MONITOR_JITTER_FRACTION=0.1
MONITOR_WATCH_ENABLED=true
MONITOR_WATCH_PROBE_TIMEOUT_SECONDS=10
MONITOR_CONCURRENCY=2
MONITOR_RUN_REPORTS=true
```

### 1.3 Monitor Target Types

| Target Type | Discovery Method | Frequency | Change Detection |
|-------------|-----------------|-----------|------------------|
| **Network Targets** | Active TLS probe | Every tick (30s) | Probe result diff |
| **Cloud Accounts** | Cloud API calls | Every tick (30s) | Config diff |
| **Repository Scans** | Git clone + scan | Scheduled (cron) | Scan comparison |
| **Container Images** | Layer scan | Scheduled (cron) | Layer diff |
| **Certificate Expiry** | Monitor target | Daily | Expiry threshold |

---

## 2. MONITORING CAPABILITIES — GAPS

### 2.1 Scheduled vs Event-Driven

| Monitoring Type | Current | Required |
|-----------------|---------|----------|
| **Scheduled (Polling)** | ✅ Yes (30s tick) | Baseline |
| **Event-Driven (Webhooks)** | ❌ No | Critical |
| **Event-Driven (CloudTrail/CloudWatch)** | ❌ No | Critical |
| **Event-Driven (Git Push)** | ❌ No | Critical |
| **Event-Driven (Container Registry)** | ❌ No | Critical |
| **Event-Driven (Certificate Transparency)** | ❌ No | Critical |
| **Event-Driven (CVE Publication)** | ❌ No | Critical |
| **Event-Driven (Network Change)** | ❌ No | Critical |
| **Event-Driven (Config Change)** | ❌ No | Critical |

---

### 2.2 Change Detection Capabilities

| Change Type | Detection Method | Real-Time? | Gap |
|-------------|-----------------|------------|-----|
| **Cloud Config Drift** | Periodic API poll (30s) | ❌ 30s delay | No event-driven |
| **Certificate Expiry** | Daily check | ❌ Daily only | No CT log monitoring |
| **Certificate Revocation** | Not monitored | ❌ | OCSP/CRL not checked |
| **Certificate Transparency** | Not monitored | ❌ | No CT log monitoring |
| **Dependency Changes** | Periodic SBOM (scheduled) | ❌ | No lockfile watching |
| **Network Changes** | Periodic probe (30s) | ❌ 30s delay | No passive monitoring |
| **Configuration Changes** | Periodic scan (scheduled) | ❌ | No config watching |
| **Crypto Algorithm Changes** | Periodic scan | ❌ | No real-time |
| **Key Rotation** | Not tracked | ❌ | No key lifecycle monitoring |
| **CVE Publication** | Not monitored | ❌ | No CVE feed integration |

---

## 3. EVENT-DRIVEN ARCHITECTURE — MISSING

### 3.1 Current: Polling Only

```python
# MonitorDaemon.run()
while True:
    for target in watch_list:
        probe(target)  # Active probe
    sleep(MONITOR_TICK_SECONDS)
```

### 3.2 Missing Event Sources

| Event Source | Integration | Status |
|--------------|-------------|--------|
| **AWS CloudTrail** | CloudWatch Events → Webhook | ❌ |
| **Azure Activity Log** | Event Grid → Webhook | ❌ |
| **GCP Cloud Audit Logs** | Pub/Sub → Webhook | ❌ |
| **GitHub/GitLab Push** | Webhook → Scan trigger | ❌ |
| **GitHub/GitLab Release** | Webhook → Scan trigger | ❌ |
| **Container Registry** | Webhook → Scan trigger | ❌ |
| **Certificate Transparency** | CT Log API → Stream | ❌ |
| **OCSP/CRL Updates** | OCSP/CRL polling | ❌ |
| **CVE/NVD Feeds** | NVD API / CVE feed | ❌ |
| **Vendor Advisories** | Vendor RSS/API | ❌ |
| **Abuse.ch / Threat Feeds** | STIX/TAXII | ❌ |
| **Abuse.ch SSL Blacklist** | SSL blacklist feed | ❌ |
| **CT Log Entries** | CT log streaming | ❌ |

---

## 4. ALERTING — BASIC ONLY

### 4.1 Current Alerting

**File:** `scripts/run_monitor.py` + `services/monitor/`

```python
# Alert channels:
# - CEF (syslog)
# - Webhook
# - Email (SMTP)
```

### 4.2 Alerting Gaps

| Alert Capability | Current | Gap |
|------------------|---------|-----|
| **Real-time Alerts** | ❌ | 30s polling delay |
| **Severity-based Routing** | ❌ | All alerts same channel |
| **Alert Deduplication** | ❌ | Duplicate alerts |
| **Alert Suppression** | ❌ | No suppression rules |
| **Alert Escalation** | ❌ | No escalation policies |
| **Alert Acknowledgment** | ❌ | No ack tracking |
| **Alert Resolution Tracking** | ❌ | No resolution tracking |
| **Alert Correlation** | ❌ | No alert grouping |
| **Notification Templates** | ❌ | Hardcoded messages |
| **Channel Preferences** | ❌ | Per-user/per-team prefs |
| **On-Call Integration** | ❌ | No PagerDuty/Opsgenie |
| **Slack/Teams Integration** | ❌ | No chatops |

---

## 5. CHANGE DETECTION — PERIODIC ONLY

### 5.1 Change Detection Methods

| Change Type | Detection | Frequency | Real-Time? |
|-------------|-----------|-----------|------------|
| **Cloud Config** | API Poll | 30s | ❌ |
| **Certificate Expiry** | Daily Check | 24h | ❌ |
| **Network Probe** | Active Probe | 30s | ❌ |
| **Repository Scan** | Scheduled | Cron | ❌ |
| **Container Scan** | Scheduled | Cron | ❌ |
| **Cloud Resource** | API Poll | 30s | ❌ |
| **Config File** | Scheduled Scan | Cron | ❌ |
| **Dependency** | Scheduled SBOM | Cron | ❌ |
| **CVE Match** | Scan-time Only | Scan-time | ❌ |

---

### 5.2 Missing: Real-Time Change Detection

| Real-Time Need | Current | Required |
|----------------|---------|----------|
| **Git Push → Immediate Scan** | ❌ | Webhook → Scan |
| **Cloud Config Change → Immediate Probe** | ❌ | CloudTrail → Probe |
| **Container Push → Immediate Scan** | ❌ | Registry Webhook → Scan |
| **Certificate Issuance → Immediate Check** | ❌ | CT Log → Check |
| **Certificate Revocation → Immediate Alert** | ❌ | OCSP/CRL → Alert |
| **CVE Publication → Immediate Rescan** | ❌ | CVE Feed → Rescan |
| **Network Change → Immediate Probe** | ❌ | Network Event → Probe |
| **Config Drift → Immediate Drift Event** | ❌ | Config Watch → Drift |

---

## 6. CONTINUOUS ANALYSIS — MISSING

### 5.1 Continuous Analysis Pipeline — MISSING

| Analysis | Continuous? | Current |
|----------|-------------|---------|
| **Risk Score Recalculation** | ❌ | On-demand only |
| **Agility Score Recalculation** | ❌ | On-demand only |
| **Quantum Risk Recalculation** | ❌ | On-demand only |
| **Drift Detection** | ❌ | Periodic only |
| **Compliance Recalculation** | ❌ | On-demand only |
| **Agility Recalculation** | ❌ | On-demand only |
| **Exposure Path Recalculation** | ❌ | On-demand only |
| **Attack Surface Recalculation** | ❌ | On-demand only |

---

## 6. CERTIFICATE MONITORING — PARTIAL

### 6.1 Current Certificate Monitoring

| Capability | Implemented | Gap |
|------------|-------------|-----|
| **Expiry Monitoring** | ✅ Daily | No real-time |
| **Expiry Alerts** | ✅ Threshold-based | No CT log |
| **Revocation Checking** | ❌ | OCSP/CRL not checked |
| **CT Log Monitoring** | ❌ | No CT log streaming |
| **Certificate Transparency** | ⚠️ Parsed only | SCTs parsed, not verified |
| **OCSP Stapling** | ❌ | Not checked |
| **Certificate Pinning** | ❌ | Not tracked |
| **CT Log Monitoring** | ❌ | No CT log streaming |
| **Wildcard Cert Tracking** | ❌ | No wildcard expansion |
| **Certificate Pinning** | ❌ | Not tracked |

---

## 6. DEPENDENCY MONITORING — MISSING

### 6.1 Dependency Change Detection

| Capability | Implemented | Gap |
|------------|-------------|-----|
| **Lockfile Watching** | ❌ | No file watching |
| **SBOM Continuous** | ❌ | Scheduled only |
| **Transitive Deps** | ❌ | Direct only |
| **CVE Matching** | ❌ | Scan-time only |
| **CVE Feed Integration** | ❌ | No CVE feed |
| **Vendor Advisory** | ❌ | No vendor feed |
| **Lockfile Change Detection** | ❌ | No file watching |
| **Transitive Crypto Propagation** | ❌ | Direct only |

---

## 6. NETWORK MONITORING — PERIODIC ONLY

### 6.1 Network Change Detection

| Capability | Implemented | Gap |
|------------|-------------|-----|
| **Active Probe** | ✅ 30s interval | Not real-time |
| **Passive Monitoring** | ❌ | No passive capture |
| **New Endpoint Detection** | ⚠️ If target in list | No auto-discovery |
| **Certificate Change** | ✅ Probe detects | 30s delay |
| **Cipher Suite Change** | ✅ Probe detects | 30s delay |
| **Protocol Version Change** | ✅ Probe detects | 30s delay |
| **New Endpoint Auto-Discovery** | ❌ | No passive discovery |
| **Passive TLS Monitoring** | ❌ | No passive capture |
| **Network Flow Analysis** | ❌ | No flow analysis |

---

## 7. CONFIGURATION MONITORING — PERIODIC ONLY

### 7.1 Configuration Change Detection

| Config Type | Detection | Real-Time? |
|-------------|------------|------------|
| **Cloud Config** | API Poll (30s) | ❌ 30s delay |
| **K8s Config** | Scheduled Scan | ❌ |
| **Container Config** | Scheduled Scan | ❌ |
| **Network Device Config** | Scheduled Scan | ❌ |
| **Application Config** | Scheduled Scan | ❌ |
| **Database Config** | Scheduled Scan | ❌ |
| **TLS Config** | Periodic Probe | ❌ |
| **SSH Config** | Scheduled Scan | ❌ |
| **VPN Config** | Scheduled Scan | ❌ |

---

## 8. RECOMMENDATIONS

### P0 — Critical

1. **Implement Event-Driven Architecture** — Webhook endpoints for CloudTrail, GitHub, Container Registry, CT Logs
2. **Implement Real-Time Alerting** — Severity routing, deduplication, escalation, on-call integration
3. **Implement CT Log Streaming** — Real-time certificate transparency monitoring
4. **Implement CVE Feed Integration** — Real-time CVE matching and alerting

### P1 — High

4. **Implement Event-Driven Scanning** — Webhooks for GitHub, GitLab, Container Registry, CloudTrail
5. **Implement CT Log Streaming** — Real-time certificate transparency
6. **Implement CVE Feed Integration** — Real-time CVE matching
7. **Implement OCSP/CRL Monitoring** — Real-time revocation checking
8. **Implement Passive Network Monitoring** — Passive TLS capture

### P2 — Medium

9. **Implement Dependency Change Detection** — Lockfile watching, SBOM diffing
9. **Implement CVE Feed Integration** — Real-time CVE matching
10. **Implement Certificate Transparency Streaming** — Real-time CT log monitoring
10. **Implement OCSP/CRL Real-Time Checking** — Real-time revocation
11. **Implement Threat Feed Integration** — STIX/TAXII, AlienVault OTX, Abuse.ch
11. **Implement Passive Network Monitoring** — Passive TLS capture

### P3 — Enhancement

12. **Intelligent Alert Correlation** — Alert grouping, deduplication
12. **Predictive Alerting** — ML-based anomaly detection
13. **Alert Fatigue Reduction** — Smart suppression, learning
14. **Cross-Source Correlation** — Correlate cloud + network + code changes
15. **Automated Response** — Auto-remediation for known patterns

---

## 8. VERDICT

**ZELNX operates on a 30-second polling loop — not continuous monitoring.** No event-driven architecture, no real-time change detection, no real-time alerting, no event-driven re-analysis.

| Monitoring Capability | Status |
|-----------------------|--------|
| Scheduled Scanning | ✅ 30s tick |
| Event-Driven Discovery | ❌ None |
| Real-Time Change Detection | ❌ None |
| Real-Time Alerting | ❌ None |
| Event-Driven Re-Analysis | ❌ None |
| Continuous Risk Recalculation | ❌ None |
| Continuous Drift Detection | ❌ Periodic only |
| CT Log Monitoring | ❌ None |
| CVE Feed Integration | ❌ None |
| Event-Driven Scanning | ❌ None |
| Passive Network Monitoring | ❌ None |
| Real-Time Alerting | ❌ None |

**To implement true continuous monitoring:** 8-12 weeks for event-driven architecture, webhook integrations, real-time alerting, CT log streaming, CVE feed integration, and continuous analysis pipeline.

---

## 9. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Monitor Daemon | `scripts/run_monitor.py` |
| Monitor Config | `docker-compose.yml` (MONITOR_* env vars) |
| Monitor Service | `services/monitor/` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Cloud Scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Container Scanner | `services/container_scanner/container_scanner/core/scanner.py` |
| Monitor Targets | `services/monitor/` |
| Drift Detection | `services/drift/drift/` |
| Daily Digest | `services/drift/drift/alerts/daily_digest.py` |
| Certificate Intel | `services/universal_crypto/universal_crypto/certificate_intel.py` |
| Network Scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Cloud Scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Container Scanner | `services/container_scanner/container_scanner/core/scanner.py` |
| Monitor Targets Config | `config/telecom_registry.json` |
| Platform Events | `services/api/api/events/platform_events.py` |
| Event Bus | `services/api/api/events/bus.py` |
| Redis Sync | `services/api/api/events/redis_sync.py` |
| Automation Bridge | `services/api/api/events/automation_bridge.py` |
---

## Round 26 update (2026-10-10) — continuous-monitoring claims re-verified

* **"Event-Based Discovery ❌" — STALE.** HMAC-verified GitHub webhook
  receiver (push events) and registry webhooks (ACR/GCR/ECR/Harbor/
  Docker Hub, HMAC or machine key) drive event-driven scanning; the
  monitor daemon adds watch-state triggers on top of schedules.
* **"Passive Network Monitoring ❌" — STALE.** `network_scanner/passive/`
  ships envoy log parsing, an Istio telemetry client, a service-mesh
  observer and passive OT capture/protocol decoding.
* **Real-time alerting — LARGELY STALE.** The AlertRouter does severity
  routing to CEF/webhook/email; monitor sweeps (reintroduction, SLA
  escalation, evidence-chain verification) alert on state, not on
  demand. On-call rotation integration and escalation-policy management
  remain product-scoped.
* **REMAIN OPEN, product-scoped:** CT-log streaming, real-time CVE feed
  push (CVE matching itself runs during SBOM/CBOM generation and the
  devsecops scans), CloudTrail webhook ingestion, lockfile watching
  (asset-level drift + inventory drift already run per scan).

## Round 34 addendum (2026-10-11) — CT-log entry ingestion BUILT (deterministic layer)

CT-log streaming splits honestly into code and configuration, and the
code half now ships:

- `services/network_scanner/network_scanner/certificates/ct_entries.py`:
  RFC 6962 `get-entries` leaf parsing (version/entry-type/3-byte DER
  length), DER certificate -> inventory payload with SHA-256 fingerprint,
  SANs, key identity and `extra["ct"]` provenance (log URL, index).
  Precertificate leaves are skipped with an explicit
  `unsupported_precert` reason rather than half-parsed; every rejected
  entry is reported with a machine-readable reason.
- `POST /certificates/ct-entries` (`ct-entries/ingest-v1`): batch ingest
  into the certificate inventory (upsert semantics, composite/hybrid
  detection rides along free). A live poller or a log-monitor export
  feeds it.
- Tests: `services/network_scanner/tests/test_ct_entries.py` — every
  assertion against a real cryptography-parsed certificate packed into
  an RFC 6962 leaf.

Still deployment-scoped, unchanged: the live poller pointed at a real
log/monitor endpoint — that is configuration (which logs, which monitor,
what credentials), not code.

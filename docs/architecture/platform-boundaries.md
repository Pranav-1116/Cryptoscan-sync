# Platform scope & honest boundaries

**Single source of truth:** `shared/shared_models/shared_models/platform_scope.py`
(served live at `GET /api/v1/platform/scope`, enforced by
`shared/shared_models/tests/test_platform_scope.py`). This page mirrors that
manifest; if they ever disagree, the manifest wins and the tests fail.

CryptoScan is an **end-to-end crypto & security-configuration platform** —
not a universal "scan everything" tool. The boundaries below are product
decisions, and they are the reason the tool is approvable in regulated
environments: **it only ever looks at key *metadata*, read-only, and chains
every observation to evidence.**

---

## What it covers

| Area | What it does |
|---|---|
| Source-tree crypto inventory | Deterministic detection of crypto API usage (algorithm, mode, key size, hardcoded keys, certificates) across Java / C# / Go / Python / JS and more |
| Network & TLS posture | Passive TLS handshake inventory, certificate posture + expiry, weak protocol detection, DNSSEC / IPsec targets |
| Containers & IaC | Image layer analysis, package/manifest parsing, embedded JARs and shared libraries, Dockerfile / IaC crypto configuration |
| Cloud accounts & tenants | AWS / Azure / GCP discovery **inside the accounts and tenants the operator has access to** — read-only, credential-scoped |
| OT/ICS | Passive protocol inventory (OPC-UA / DNP3 / Modbus / IEC 61850) with a verified zero-packet promise to OT networks |
| Payment HSM / PCI | HSM key inventory with ceremony provenance, TR-31 parsing, audit-trail ingestion, PAY policy rules — key *metadata* only |
| Vendor & supply-chain | Vendor crypto discovery (API scan, CBOM import, questionnaire, public posture) with 0–100 risk scores |
| Certificates & PQC readiness | Certificate fingerprint inventory, quantum risk analysis (Shor/Grover, HNDL, Mosca deadlines), evidence-supported PQC migration readiness |
| Shared layers | Evidence chain, normalization (IANA / CBOM / SPDX), deterministic YAML policy, drift & CI gates, graph, remediation, compliance reporting, 24/7 live monitoring |

---

## What it is NOT (honest boundaries)

1. **Not general application SAST / source-code hacking.** We do not hunt
   SQLi, XSS, buffer overflows, or auth flaws in application code. We
   inventory **crypto usage and security configuration** — a narrow,
   deterministic, evidence-backed subset of code analysis.

2. **Not malware analysis.** We identify crypto *libraries and
   configurations* inside binaries and containers. We do not analyze
   malware or malicious behavior.

3. **Not SIEM behavior analytics.** We emit findings to SIEM / CEF as an
   **outbound alert sink**, but we do not perform behavior analytics,
   correlation hunting, or endpoint telemetry analysis.

4. **Not mainframe core banking.** AS/400 and COBOL assets are out of
   scope — we do not scan mainframe core banking systems.

5. **Not employee endpoint scanning.** No agents on, and no scans of,
   employee workstations/endpoints.

6. **Not "scan AWS the company".** We scan only the **accounts/tenants you
   have credentials for**. External surface is covered only via public
   internet scanning of explicitly configured targets (hostnames/IP ranges)
   — never the provider's infrastructure or other tenants.

---

## Access model

- **Read-only, always.** Every collector (source, network, container,
  cloud, OT, HSM, vendor) only reads. OT scanning sends **zero packets** to
  OT networks. Nothing is modified, written, or deployed.
- **Credential-scoped.** We connect with the operator's credentials to
  exactly the accounts, tenants, repos, registries, and hosts they
  configure. Cloud inventory is the credential-visible surface, not the
  whole provider.

---

## Invariants (tested)

1. **Read-only collection** — collectors never mutate the scanned estate.
2. **Evidence-chained observations** — every finding carries content/chain
   hashes; packs and transfers are digest-verified and tamper-evident.
3. **Key material is never retrieved** — we inspect key *metadata*
   (algorithm, key size, purpose, rotation, ceremony provenance). Private
   keys, secret values, and key material never leave the scanned estate.
   Evidence packs and transfer payloads use strict field whitelists
   (tested: fake secrets planted in source records do not appear in any
   pack output).
4. **Policy is never decided by AI** — rules are versioned YAML
   (NIST / FIPS / NSA / PCI-DSS / HIPAA / ISO); evaluations are
   deterministic and auditable.
5. **Honest status, never faked** — unscannable or untestable targets are
   reported `BLOCKED` / `NOT_EVALUATED`, never guessed, never assumed PASS.

---

## Why this matters for banks

A bank can deploy CryptoScan *next to* its crypto estate (including payment
HSMs and cloud tenants) because the compliance story is simple and
verifiable: the platform inspects **key metadata, not key material**, makes
no changes to any system, and can prove — through the evidence chain and
the whitelist tests — that nothing sensitive is ever extracted or exported.
The boundaries are enforced by tests, not just documented here.

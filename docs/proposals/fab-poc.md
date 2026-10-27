# Proof of Concept — cryptographic visibility & PQC readiness for a UAE bank

**Prepared for:** First Abu Dhabi Bank (or any UAE tier-1/mid-tier financial
institution) · **Proposed by:** CryptoScan / ZELNX · **Duration:** 2 weeks ·
**Effort from the bank:** one network range + one read-only cloud role +
2 × 1-hour workshops.

---

## Why now

- The UAE Cyber Security Council runs a **national post-quantum migration
  program** (national Crypto Discovery Tool, May 2026); banks sit inside
  "critical infrastructure" and the "what cryptography do you run?" question
  is already being asked at national level.
- CBUAE has shown it regulates by deadline (Notice 2025/3057 OTP phase-out,
  completed early by FAB). Post-quantum timelines (NIST IR 8547: 112-bit
  legacy disallowed after 2030, hard stop 2035) are the next compliance
  clock — and **inventory is step zero of every such mandate**.
- Most institutions cannot answer that inventory question for their own
  estate. This PoC produces the answer, with evidence, in two weeks.

## What the PoC delivers (all real output, no slides-only)

1. **Crypto Bill of Materials (CBOM)** of the agreed scope — every TLS
   endpoint, certificate (expiry, key size, signature, chain), and cloud KMS
   key (AWS KMS / Azure Key Vault, read-only), deduplicated and
   evidence-linked.
2. **Quantum-risk view** — which families are Shor-exposed (RSA, ECDSA) vs
   Grover-relevant (AES, HMAC), mapped to NIST IR 8547 transition buckets
   (immediate / by-2030 / by-2035).
3. **Migration roadmap pack** — the existing roadmap engine folded across
   IT + cloud estates, board-ready, with HNDL-oriented prioritization.
4. **Evidence pack** — hash-manifested export (SHA-256 manifest, examiner
   verifiable) suitable for regulator or internal-audit consumption.
5. **Optional telecom module** — if the bank operates private 5G/roaming
   edges: 5GC/roaming verdicts incl. SEPP hybrid-PQC readiness.

## How it runs (on-prem, two containers)

The engagement runs from `deploy/poc/`: a two-container compose stack (API +
dashboard, SQLite in a named volume), a fill-in env template, and a
day-by-day operator checklist (`deploy/poc/CHECKLIST.md`). Everything stays
inside the bank's tenancy; the end-of-engagement `down -v` destroys every
byte. Air-gap install is documented for disconnected environments.

## How (read-only by construction)

- Network probes are TLS/certificate handshakes — no exploitation, no
  credential harvesting, no agents installed on bank servers.
- Cloud collection uses an AWS/Azure **read-only role** (kms:List*,
  kms:Describe* / Key Vault Reader). Key material is never fetched, never
  stored — metadata only (algorithm, size, state, origin).
- Everything runs on-premise or in the bank's subscription; data never
  leaves the tenancy. The platform is air-gap capable.

## Success criteria (agreed up front)

- ≥ 90% of in-scope endpoints and cloud key vaults inventoried, with an
  honest skipped-list (every gap is named with its reason — the tool does
  not guess).
- CBOM + roadmap accepted by the bank's crypto/CISO owner as "the first
  complete answer to our crypto inventory question".
- Evidence pack verifies end-to-end (hash manifest) by the bank's own audit
  function.

## What is explicitly out of scope (and never faked)

- Certifications of the product (ISO/SOC 2) — controls are auditable
  in-repo; external attestation is a company-level track.
- Key-material extraction, exploitation, or pentest-grade probing.
- Collector coverage beyond the agreed scope (e.g., mainframe/DB TDE) —
  named as roadmap, not silently absent.

## Commercial path after the PoC

PoC fee credited against the first platform year. Platform scope: continuous
scanning (Prometheus metrics + alert rules), ITSM/SIEM delivery
(ServiceNow incidents, Splunk HEC), SSO (OIDC/SAML/LDAP/SCIM) with the
auditor role and audit-export packs, per-regulator artifact generation.

## Delivered in this repo (as of 2026-09-12)

Every item above exists as code + tests, not slides:

| Proposal item | In the repo |
|---|---|
| CBOM of agreed scope | estate CBOM engine + `GET /scans/{id}/cbom`, CycloneDX 1.5 ([user guide](../user-guide/cbom-export.md)) |
| Quantum-risk view | Shor/Grover families → NIST IR 8547 buckets in the quantum/migration views |
| Migration roadmap pack | roadmap engine across IT + cloud + telecom (`GET /telecom/roadmap`) |
| Evidence pack | now three hash-sealed deliverables: **audit pack** (`/audit-export/pack`), **exit report** (`/audit-export/exit-report`, deterministic SHA-256, SC-1…4 scored from data), **engagement archive** (`/audit-export/engagement-archive`) — the client's audit function verifies with any sha256sum-style check ([guide](../user-guide/audit-pack-and-exit-report.md)) |
| Optional telecom module | shipped: 5GC/roaming/EPC/IMS verdict engine, SEPP hybrid-PQC readiness (`pqc_ready` only when actually probed), carrier packs ([guide](../user-guide/telecom-scanning.md)) |
| Two-container on-prem run | `deploy/poc/` — compose stack, env template, day-by-day operator checklist |
| Read-only by construction | read-only cloud roles, TLS-handshake-only probes, key metadata never key material (enforced by tests) |

The success criteria above are now **machine-scored**: the exit report
evaluates coverage ≥ 90% from the computed worst estate (skips named with
reasons), pack verifiability from its manifest, and acceptance **only** from
a human `accepted_by` name — never inferred.

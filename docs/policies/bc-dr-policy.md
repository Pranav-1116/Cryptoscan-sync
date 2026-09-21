# Business Continuity & Disaster Recovery Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: Engineering Director]
· **Applies to:** all production environments of CryptoScan
· **Next review:** [ORG: YYYY-MM-DD] · **Criteria:** TSC CC8.1, CC9.1,
CC9.3, A1.1

## 1. Purpose

Define how CryptoScan keeps scanning, alerting and reporting available
throughout failures, and how it recovers — with **drillable, evidenced**
procedures rather than shelf documentation.

## 2. Objectives

| Metric | Target | Basis |
|--------|--------|-------|
| **RTO** (recovery time objective) | **4 hours** | CBUAE CSF expectation for payment-adjacent systems; `docs/runbooks/dr-recovery.md` |
| **RPO** (recovery point objective) | **1 hour** | PostgreSQL streaming replication lag bound; CBUAE CSF |
| Availability target | [ORG: 99.5% monthly for the API, 99.0% for reporting — confirm against client SLAs] | service agreements |

These targets drive the client banks' own CBUAE obligations (RTO 4 h /
RPO 1 h), so they are contractual in effect even where the client
contract is silent.

## 3. Architecture controls

1. **Active/standby PostgreSQL** with streaming replication
   (`docker-compose.prod.yml` / `docs/admin-guide/production.md`);
   failover is documented in `docs/runbooks/dr-recovery.md`.
2. **HA for the stateless layers** — the API and frontend are
   horizontally scalable behind the load balancer; the compose topology
   and the `deploy/ha/` scripts define the target layout.
3. **Backups.** Automated [ORG: daily] backups of the database, Redis
   persistence and the evidence chain; backups are stored off-host and
   access is restricted to [ORG: named roles].
4. **The evidence chain is a recovery asset.** Because it is
   append-only and Merkle-verifiable, a recovery can *prove* which
   pre-failure state it restored: post-recovery verification compares
   chain heads.

## 4. Backup verification and DR drill

1. **Restore verification** at least [ORG: monthly]: a backup is
   restored to an isolated environment and its integrity (including
   evidence-chain verification) is checked.
2. **DR drill** at least [ORG: semi-annually]: `deploy/ha/drill.sh`
   executes the full failover sequence on a docker-capable host and —
   when run under the evidence runner — appends the drill result to the
   signed production-evidence chain, so each drill is itself an
   auditable artifact. A drill that cannot run (no docker host) records
   a clean SKIP rather than a silent gap.
3. Drill findings are tracked to closure like any vulnerability
   (Vulnerability Management Policy), with a target of [ORG: 90 days]
   for Critical/High items.

## 5. Continuity

1. **People:** [ORG: define the continuity roster — who can declare a
   disaster, who can fail over, and the coverage plan for their absence].
2. **Vendors:** critical third parties (hosting, HSM, IdP) are assessed
   for their own continuity under the Vendor & Third-Party Risk Policy.
3. **Communications:** a declared disaster triggers the incident comms
   tree (Incident Response Policy) with client notification per the
   contractual SLA.
4. **Return:** fail-back to the primary site is a planned, tested step,
   not an improvisation; the evidence chain is re-verified after
   fail-back.

## 6. Evidence

- Drill runs and restore verifications: recorded in the production
  evidence chain where executed under the runner; otherwise in [ORG:
  ops log location] with the same fields (timestamp, environment,
  outcome, verifier).
- The DR runbook (`docs/runbooks/dr-recovery.md`) is versioned with the
  code and changes follow the Change Management Policy.
- For the SOC 2 window, the auditor expects at least [ORG: two] drill
  cycles with results inside the window.

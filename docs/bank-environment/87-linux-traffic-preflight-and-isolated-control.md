# 87 — Linux traffic preflight and isolated control validation

[Previous: traffic/storage measurement](86-network-traffic-storage-and-control.md) · [API](../api-reference/traffic-control.md) · [Operator runbook](../runbooks/traffic-control.md) · [Engineering evidence](../readiness-evidence/traffic-control-2026-10-26.md)

## What is built now

The existing **Network** page now adds **Linux traffic control: preflight & isolated validation**, using the existing tenant/authentication/assurance store. No new service, continuous collector, privileged daemon or remote executor is introduced.

1. Start from a measured, retained traffic proposal from Guide 86, no older than five minutes, under a currently approved sampling scope and active system/environment.
2. Create a five-minute-or-shorter **read-only preflight request**, pinning the proposal record and original measurement/context. Explicitly declare 1–8 canonical management IP destinations; no DNS/subnet scanning or discovered “complete management inventory.”
3. An ordinary-user operator runs fixed `ip`/`tc` read-only commands. The resulting packet records selected interface identity, existing qdisc summaries, effective route devices for each declared IP, executable/source hashes, and boot/network/mount namespace identifiers. Failed sources are gaps, never absence.
4. Import and retain the immutable preflight. The server recomputes blockers and verifies the original source/approval closure.
5. A human proposes **isolated validation only**, selects a different current estate reviewer, and provides a reason. Only that reviewer with current `assurance.review` authority can approve once. Every mutation is audited atomically.
6. Download a short-lived namespace-only packet. The ordinary-user CLI creates fresh user/network namespaces. Only their loopback can be activated or changed. A fixed owned TBF root is added, read back, held for 1–5 seconds, then removed only if the exact owned handle/rate remains. Matching default-policy readback is required for success.

The UI exposes explicit steps, original JSON downloads, retained reports/history, and no host apply button. It makes no automatic target calls. Raw preflight JSON is submitted as text, preserving uint64 namespace identifiers. Private-scope changes abort/clear pending display/download state; server authorization remains the authority.

## Two different safety decisions

| Decision | Meaning | Not implied |
|---|---|---|
| `recorded_checks_complete` | The declared read-only checks resolved and source interface/context matched | Complete management coverage, authenticated device identity, policy compatibility or authorization to change the source host |
| Separate-human `APPROVED_ISOLATED_VALIDATION` | Permit the bounded, local, fresh-namespace mechanism test | Approval of the original draft as a production change |
| `APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE` | Exact TBF readback and matching rollback were observed in the isolated child | Measured throughput enforcement, real-interface success or production qualification |

An existing root policy is **recorded and preserved**, not replaced. It blocks host enforcement but need not prevent a completely separate loopback namespace test. A management route using the selected source interface also remains an explicit host blocker. Every report always includes device enrollment, source authenticity, incomplete management inventory and missing real-host executor blockers. **There is no state that authorizes real-host enforcement.**

Qdisc summaries are not a complete class/filter/ingress/firewall/bridge/tunnel topology inventory. An effective route selection is not reachability or a guarantee about the return path, routing changes, policy routing for all principals, multipath, bastions or out-of-band access. Unsupported/ambiguous routes remain unresolved. Management completeness is always false.

## Native sandbox result — blocked, not upgraded to success

The actual engineering sandbox exposes `eth0` with an existing `pfifo_fast` root policy; its original bytes were unchanged before/after the new witness. Declared `127.0.0.1` routed through `lo`; this is a sandbox diagnostic, not a bank management route.

User/network namespace creation and child loopback activation succeeded. The kernel rejected TBF: **“Specified qdisc kind is unknown.”** The retained native result is `REFUSED_OR_FAILED`, CLI exit 2, with no verified qdisc apply or rollback. No module was loaded, no sudo was used, and no parent-interface fallback was attempted. Successful apply/readback/rollback is covered only by **synthetic command fixtures**, not a native kernel success claim.

The local witness uses synthetic proposal/review IDs and hashes. It is not an independently approved change or an enrolled device credential. Hashes and immutable revisions establish engineering integrity, not producer authenticity. Do not send credentials/private keys.

## Next boundary

Before real enforcement, agree the actual target, enroll its identity and authenticated device adapter, inventory and independently review management exclusions and existing policy/class/filter ownership, define revocation/execution leases and rollback/out-of-band recovery, and qualify an owned disposable target with native throughput and negative tests. Owned PostgreSQL review/revocation races and audit rollback are covered by synthetic engineering tests; independent operational acceptance and production database qualification remain pending. Do not apply these test packets to real interfaces, routers, firewalls or cloud resources.

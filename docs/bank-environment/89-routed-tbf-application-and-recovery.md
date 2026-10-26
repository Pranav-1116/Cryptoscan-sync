# 89 — Routed disposable network, application impact and failure recovery

[Previous](88-disposable-linux-tbf-qualification.md) · [Runbook](../runbooks/routed-tbf.md) · [Implementation](../../tools/routed_tbf/README.md) · [Evidence](../readiness-evidence/routed-tbf-2026-10-26.md)

## Built boundary

One externally NIC-less Linux VM contains sender, gateway, receiver and management
network namespaces linked only by guest-internal veth pairs. The gateway forwards
sender→receiver traffic and owns an explicitly selected egress TBF. Management
uses a different link and independent echo endpoint; a third unrelated test policy
is installed on the gateway's sender-facing link and must remain unchanged.

This exercises actual forwarded packets, not loopback-only shaping or synthetic
command responses. It remains an emulated laboratory, not physical NIC/wire-rate,
router/firewall or customer-host qualification. No host traffic-control writes,
module loading, sudo, host networking or disk/directory forwarding is permitted.

## Application evidence and predeclared gates

The user selected the engineering profile before the first measurements. Exact
thresholds are committed in [acceptance.json](../../tools/routed_tbf/acceptance.json):
UDP received payload 80–110% of 10/5 Mbps; TCP aggregate 70–110%; unshaped baseline
and recovery at least 30 Mbps, recovery at least 80% of baseline; management echo
at least 99% of scheduled probes delivered, p95 ≤100 ms, p99 ≤250 ms; withdrawal
response ≤5 seconds. These are engineering gates, not a bank SLA.

Eleven workload phases include UDP baseline/recovery and 10/5 Mbps caps,
256/1200/1400-byte payloads, 1/5/16-packet microbursts, TCP baseline/recovery,
one/four TCP connections and capped four-flow TCP at both rates. Each receive
window is ten seconds after one warmup second—longer than v1's four-second window,
**not a soak/24-hour test**. A half-second UDP drain is retained separately in the
loss denominator. Latency probes run under load on both data and management paths.

UDP loss uses sent successful datagrams versus deduplicated received datagrams
including warmup/drain; phase throughput uses receive bytes inside the measurement
window. TCP counters are bytes/send calls, not inferred IP packet counts;
retransmissions come from sender TCP_INFO. TCP does not receive an invented
packet-loss percentage. Per-flow byte totals are retained, not a fairness guarantee.
Latency p95/p99 are nearest-rank echo RTT statistics, not application transaction
latency; raw per-probe samples are not retained. Data latency, loss and retransmission
results are published without a lossless-delivery/application SLA gate. Management
"unchanged" means preserved topology/policy and meeting the agreed delivery/latency
bounds—not literally identical latency across phases.

## Recovery and refusal semantics

An independent guest watchdog enforces heartbeat expiry and a monotonic local
controller lease. Actual injections cover controller SIGKILL, lost heartbeat
(simulated control connection loss) and lease expiry. Successful withdrawal needs
exact owned handle/options and matching interface identity, default-policy readback
and an additional measured post-recovery UDP run. Management is probed throughout.

Interface recreation and a replacement foreign policy are **expected refusal
cases**, not successful recovery. The watchdog must preserve the replacement policy
and report refusal within five seconds. Test-harness cleanup afterward is explicitly
separate and cannot turn that case into recovered. The aggregate passing verdict
therefore says `LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES`; it never says all
failure modes recovered. A missing watchdog result or unresolved unexpected case
makes the qualification fail.

## Conservative policy safety

Fixed selected interface, approved management destinations, qdisc/class/filter,
ingress/egress filter, default rule-set and effective management-route checks are
required. Existing HTB class/filter trees, clsact filters, management-interface
selection, undeclared management destinations, policy-routing rules and multipath
management routes are exercised as actual negative cases. Unknown configurations
are refused, not automatically reconciled. This pinned `tc` emits class text;
nonempty text is retained as an unresolved blocker, never parsed as absence. Only
its known successful empty class listing is normalized to an empty list.

## Authenticated authority—not production authority

The operator uses distinct issuer/reviewer/adapter Ed25519 keys in a private local
lab authority. Grants bind tenant, enrolled logical target, exact boot bundle,
acceptance profile, nonce and expiry. Explicit simulated-reviewer approval precedes
atomic one-use redemption. Revoked/expired grants stop the bounded VM. Signed
receipts require an explicitly pinned adapter public key for verification.

This is an authenticated **local lab protocol**, not networked enrollment/mTLS,
physical-device attestation, independently approved production change or hardened
multi-tenant authority. A trusted local store owner controls all three keys.
Future real adapters still require external enrollment governance, transport
identity, protected key custody, clock/ledger rollback defenses, independent human
approval, management inventory and out-of-band recovery. No real-host adapter is
introduced here and all production flags remain false.

## Build trust and independent work

Locked source/byte commitments and license-file evidence are recorded. This does
not verify upstream authenticity, approve licensing or establish a current security
baseline. The prebuilt emulator and copied system runtimes require separate review.
The external review intake requires an explicitly pinned reviewer key and a distinct
recorded environment, and lists changed binary hashes. It authenticates the review
record, not the reviewer's competence or physical environment. Second-environment
execution and independent launcher/runtime review must remain pending until a
separate operator actually supplies those results. They cannot be self-certified
by this implementation.

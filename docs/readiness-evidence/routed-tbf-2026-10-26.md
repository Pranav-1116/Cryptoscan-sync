# Routed disposable TBF — application impact and recovery evidence

[Guide 89](../bank-environment/89-routed-tbf-application-and-recovery.md) · [Operator runbook](../runbooks/routed-tbf.md) · [Implementation](../../tools/routed_tbf/README.md) · [Review/update gate](../../tools/routed_tbf/SECURITY-REVIEW.md)

## Delivery status against the six requested improvements

| Requested improvement | Delivered and exercised | Boundary / remaining work |
|---|---|---|
| Routed isolated topology | Actual sender→gateway→receiver forwarding, separate management link, unrelated sentinel policy; two fresh final VM boots | One emulated Linux VM with guest network namespaces/veth; no physical NIC, external/customer connectivity or independent host |
| Application impact | Eleven phases per boot: UDP/TCP, one/four TCP flows, 256/1200/1400-byte payloads, 1/5/16-packet bursts, ten-second measured windows, RTT tails, UDP loss, TCP_INFO retransmissions | Minutes, not a soak; echo RTT is not transaction latency; no losslessness/fairness/application SLA |
| Failure recovery | Actual controller SIGKILL, stopped heartbeat, lease expiry, interface recreation and policy replacement; three additional post-withdrawal traffic measurements per boot | Heartbeat loss models connection failure, not a deployed remote control transport. Identity/policy replacement is preserved and **not recovered** |
| Policy/management safety | Actual HTB class/filter, clsact, management-interface/destination, policy-rule and multipath negative cases; independent management probes throughout | Fixed IPv4/netfilter-free fixture; not general host firewall/bridge/tunnel/VRF/management-inventory qualification |
| Authenticated authority | Local three-role Ed25519 lab enrollment, explicit simulated reviewer step, bound lease, one-time redemption, live revocation, signed adapter receipts; negative tests plus actual VM revocation | Shared trusted local store owner, not independent humans, networked enrollment, physical attestation or production approval |
| Build trust / independent validation | Fresh locked build, archive/license evidence, environment record, build comparison and signed external-review intake | **Independent reviewer and second supported environment have NOT run.** Licensing/security/provenance review remains pending/UNKNOWN; no production qualification |

## Predeclared acceptance — unchanged after failures

The user selected the engineering profile before measurement. [acceptance.json](../../tools/routed_tbf/acceptance.json) requires:

- UDP received payload 80–110% of configured 10/5 Mbps; TCP aggregate 70–110%.
- UDP/TCP baseline and recovery ≥30 Mbps; recovery ≥80% of corresponding baseline.
- Management delivery ≥99% of scheduled probes, p95 ≤100 ms and p99 ≤250 ms.
- Owned-policy withdrawal/readback or a safe explicit refusal within five seconds.
- Exact installed policy/options, advancing kernel counters, explicit rollback, unchanged unrelated/management policy, unchanged parent context/policy and exact source/binary bindings.

No data-path latency/losslessness/application SLA was agreed. Such observations are retained, not silently discarded or promoted to a quality guarantee. The ten-second post-recovery validation window follows withdrawal; it is not itself completed within the five-second withdrawal deadline.

## Actual final application measurements

All figures below are received **application payload Mbps** through the guest gateway, not wire rate or a physical NIC benchmark.

| Workload | Run 01 | Run 02 |
|---|---:|---:|
| UDP baseline, 1200 bytes / burst 5 | 40.5648 | 40.1962 |
| TCP baseline, four connections / burst 5 | 45.9024 | 46.3632 |
| UDP, 10 Mbps cap / 1200 bytes | 9.6557 | 9.6566 |
| UDP, 5 Mbps cap / 1200 bytes | 4.8269 | 4.8269 |
| UDP, 10 Mbps / 256 bytes / burst 16 | 8.5862 | 8.5856 |
| UDP, 10 Mbps / 1400 bytes / burst 16 | 9.7026 | 9.7037 |
| TCP, 10 Mbps / one connection | 9.5568 | 9.5591 |
| TCP, 10 Mbps / four connections | 9.5746 | 9.5608 |
| TCP, 5 Mbps / four connections | 4.7784 | 4.8027 |
| UDP after rollback | 38.5699 | 41.3414 |
| TCP after rollback | 44.2896 | 46.0022 |

Both final receipts have no blockers and verdict **`LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES`**, not “all failures recovered.” Runs took 209.006 and 207.530 host seconds. No competing compilation/test suite ran during either final workload sequence.

### Management and application impact — do not hide the adverse results

- Each final boot delivered **3,660 / 3,660 scheduled management echo probes**, including the three extra recovery phases and all fault drills. Maximum per-phase management p95/p99: Run 01 **2.902 / 19.526 ms**; Run 02 **3.364 / 10.446 ms**. These satisfy the agreed bounds, not identical-latency or bank-management guarantees.
- Shaped data-path echo p99 reached **153.779 ms** and **156.941 ms**. Many scheduled data-path probes were missed while waiting for previous responses; sent/received/missed denominators remain in each phase. Tail statistics are conditional on received probes.
- TCP sender retransmissions were **199 / 325 / 224** in Run 01 and **199 / 314 / 224** in Run 02 for one-flow 10 Mbps / four-flow 10 Mbps / four-flow 5 Mbps, respectively.
- Overloaded UDP is **not lossless**: for example, Run 01's 1200-byte 10/5 Mbps cases lost about **73.9% / 87.7%** of successful sent datagrams over the warmup+measurement+drain accounting interval. Kernel drops and sender backpressure remain visible. Offered load is bounded above by 48 payload Mbps, not assumed delivered at that rate; actual sender counts are retained.

These results prove narrow enforcement and protected-link behavior, not acceptable performance for every application. TCP/latency/loss/fairness tuning requires a separately agreed application acceptance profile.

## Native failure and refusal results

| Injection | Run 01 response | Run 02 response | Exact result |
|---|---:|---:|---|
| Controller SIGKILL | 0.898 s | 0.909 s | Owned policy removed; default readback; post-withdrawal UDP meets gates |
| Lost heartbeat (connection-loss simulation) | 0.973 s | 0.972 s | Same independent-watchdog recovery |
| Controller authorization expiry | 0.858 s | 0.885 s | Same independent-watchdog recovery |
| Interface recreation | 1.166 s | 1.151 s | `REFUSED_IDENTITY_CHANGED`; replacement policy preserved; **not recovered** |
| Foreign policy replacement | 0.944 s | 0.852 s | `REFUSED_POLICY_CONFLICT`; foreign policy preserved; **not recovered** |

The test harness's later foreign-policy cleanup is separately labeled; it is not counted as controller rollback. Management and the unrelated sender-facing sentinel policy were preserved. Recorded parent qdisc policies and boot/network/mount context match before/after every final run; no parent tc write, module load or privilege escalation occurred.

An additional **actual VM revocation** drill revoked the redeemed host-side lab lease after ten seconds. Termination/reaping completed about **0.228 seconds after revocation committed**: [check](routed-tbf-2026-10-26/revocation-check.json), [signed failed receipt](routed-tbf-2026-10-26/revocation/result.json). Verdict remains `INCONCLUSIVE_OR_FAILED` with `LEASE_REVOKED_OR_EXPIRED_VM_TERMINATED`. This is bounded VM disposal, **not guest rollback readback**.

## Retained failures and load-generator correction

The [first complete routed profile](routed-tbf-2026-10-26/failed-initial-profile/result.json) failed the fixed headroom/recovery gates: UDP baseline **29.176 Mbps**, TCP baseline **20.278 Mbps**, UDP/TCP recovery **29.577 / 21.747 Mbps**. Its raw serial, signed failed receipt and exact differing guest/report source snapshots are retained.

One-packet/200-microsecond send pacing was too expensive for unshaped headroom on this one-TCG-CPU forwarded workload. Baseline/recovery generation was changed to bounded five-packet/one-millisecond batching, with capped one-packet and burst-16 variants retained. **The acceptance thresholds were not lowered.** A fresh locked rebuild and two entirely new scopes/boots then passed. Workloads differ, so this is not a same-workload product optimization or ≥20% performance-target claim.

Two earlier guest diagnostic failures involved this iproute2 version's non-JSON class output. [Diagnostic 01](routed-tbf-2026-10-26/diagnostic-01/result.json) and [02](routed-tbf-2026-10-26/diagnostic-02/result.json) remain failures. The current adapter normalizes only a known successful empty class listing; nonempty class text is retained as an unresolved blocker. A command failure or missing route/qdisc/filter result never becomes absence.

## Build, test and provenance records

- Fresh full locked build **exit 0**: [record](routed-tbf-2026-10-26/build-record.json), [manifest](routed-tbf-2026-10-26/bundle-manifest.json), [compiled config](routed-tbf-2026-10-26/kernel.config). Linux 6.12.58 with built-in TBF/veth/netns, one QEMU TCG CPU, 256 MiB guest RAM; PCI/modules/netfilter disabled. QEMU is a hash-pinned prebuilt artifact, not independently attested.
- Final bundle-manifest byte SHA-256: `ba247fa6fa7cfa25c8939dc1815c93a77104cf987fe34e0312058e13d2c8b22e`.
- Final signed-receipt byte SHA-256: Run 01 `12065c93f551077767efc39b6e714f9523ac6ab7fa4ef2d5b524cd3b9a55f26b`; Run 02 `9010928b30e5c089a03bc0b6b58a1a52daf2ee7c0dfcb297b09042d600903117`.
- Exact additive candidate: **201 focused tests passed, six warnings**, comprising 82 new tests plus 119 prior disposable/control/resource regression tests. [Output](routed-tbf-2026-10-26/python-tests.txt), [JUnit](routed-tbf-2026-10-26/python-tests.xml). This is not the entire repository suite or bank acceptance.
- Static/format/environment checks and offline receipt/artifact verification are retained in this directory. Actual GCC static builds use `-Wall -Wextra -Werror`.
- [Dependency evidence](routed-tbf-2026-10-26/dependency-review.json) records license-file commitments for six source archives; the QEMU archive had **no discovered license file**, explicitly UNKNOWN. License/security/upstream authenticity reviews remain pending; system/transitive runtime inventory is not a complete licensed-component SBOM.
- [Local validation record](routed-tbf-2026-10-26/local-validation.json) supplies actual environment and binary hashes for future comparison. It explicitly has no independent reviewer or completed launcher/runtime review.

Large binary/build/cache trees and private authority keys are intentionally not committed. The runbook reconstructs them; recorded boot hashes are not independently rehashed by the offline artifact checker without the external bundle. The two VM boots are repeated trials on **one environment**, not independent reproduction.

## Offline engineering verification

```bash
.venv/bin/python docs/readiness-evidence/routed-tbf-2026-10-26/verify-artifacts.py
```

The checker validates retained file commitments, both source-bound signed local-adapter receipts, serial/report/acceptance closure, initial failed thresholds/source snapshots and native revocation. [Public lab keys](routed-tbf-2026-10-26/public-keys.json) are not independently attested trust anchors. For separate CLI verification, pin the enrolled adapter key through a trusted channel rather than trusting a key supplied by an arbitrary receipt.

All **5,006 outside-owned fingerprints and 499 unrelated tracked edits/deletions were preserved**. The previous v1 fixture/evidence, application code and workflows are unchanged. This increment is additive tooling/docs/evidence, not a new production service, discovery collector, dashboard or real-host adapter.

## Still blocked / not claimed

Independent second-environment reproduction, independent launcher/runtime review, upstream authenticity, complete license/security review, protected custody, networked/device enrollment, independent human change approval, real-host policy/management safety, out-of-band recovery and production authorization are **not complete**. The local authority store/clock/owner remain trusted; its I/O failures may leave incomplete receipts and must never be treated as success. Replacement identity/policy cases remain not recovered. No production flags are enabled, no six-BOM completeness or product optimization target is established, and no 24/7 staffing/SLA is invented.

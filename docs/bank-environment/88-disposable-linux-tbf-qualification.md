# 88 — Scoped disposable Linux target with measured TBF enforcement

[Previous: preflight and namespace review](87-linux-traffic-preflight-and-isolated-control.md) · [Runbook](../runbooks/disposable-tbf.md) · [Fixture source](../../tools/disposable_tbf/README.md) · [Evidence](../readiness-evidence/disposable-tbf-2026-10-26.md)

## What changed

The sandbox host kernel could not create TBF. Repeating the test in a container would inherit that same kernel and would not resolve the blocker. This increment builds a **different, disposable Linux VM kernel** with TBF compiled in, then measures actual generated traffic through its policy. It does not modify or load anything into the sandbox/customer kernel.

The target is a diskless x86_64 VM with one emulated CPU, 256 MiB RAM, no NIC, no disks, no management network and no host-directory/device passthrough. Only guest loopback carries test traffic. All process inputs are committed/hash-pinned; an ordinary-user host launcher requires Landlock/seccomp and refuses elevated/capability-bearing parents. There is no host-interface argument, custom emulator flag, remote executor, production apply endpoint or new dashboard.

## Explicit phasewise qualification

1. **Build:** compile locked Linux 6.12.58 with built-in TBF and package explicit runtime files into an initramfs. Large binaries stay outside Git. Record kernel/config/initramfs/emulator/launcher/runtime hashes.
2. **Scope:** create a named, bundle-bound ten-minute **local engineering** scope. Run only with its canonical hash and explicit disposable-VM acknowledgement. This does not inherit a production approval from the previous resource proposal or namespace-review packet.
3. **Baseline:** generate paced synthetic 1,200-byte UDP payloads inside the guest, offer at most 48 payload Mbps, discard one warmup second and count actual received packets/bytes over four seconds.
4. **10 Mbps trial:** add owned TBF handle `7e01:` to guest `lo`; verify rate, collect receiver and kernel counters, delete only the exact owned policy, verify the default policy is restored.
5. **5 Mbps trial:** repeat independently at the second declared rate, with matching rollback again.
6. **Recovery:** measure unshaped receive throughput after removal. The guest reboots and the emulator exits; an outer deadline terminates/reaps a stuck VM. Namespace/process exit is not substituted for explicit policy readback.
7. **Offline verification:** bind the scope, boot bundle, serial bytes, measured receipt and deterministic report. Missing/duplicate/nonfinite frames, changed inputs, inconsistent counters, scope expiry or context/timing conflicts cannot yield a verified verdict.

## Acceptance criteria — fixed before final runs

| Gate | Required |
|---|---|
| Unshaped workload headroom | Baseline receive payload ≥30 Mbps |
| Each cap | Actual received payload between 80% and 110% of declared 10/5 Mbps |
| Kernel evidence | Exact stable TBF handle/rate; byte/packet/overlimit counters advance; kernel byte/packet deltas cover received payload counts |
| Rollback | Every trial returns to the original default policy; final rollback readback true |
| Throughput recovery | Restored receive payload ≥30 Mbps and ≥80% of the original baseline |
| Probe integrity | Exact payload/packet/attempt denominator; no fatal send, receive or invalid-payload errors; no unshaped sender backpressure |
| Timing/isolation | Actual guest/host timing consistent, parent boot/network/mount context unchanged, exact scoped nonce and boot/runtime input hashes stable |

Rates are **application received payload Mbps**, not physical wire throughput. TBF accounts packet overhead and burst/timer behavior; therefore a 10 Mbps queue can deliver roughly 9.66 payload Mbps for this workload. These declared engineering bands are not a bandwidth SLA. Expected `ENOBUFS`/`EAGAIN` queue backpressure during shaping is explicitly retained separately from fatal socket errors; kernel drops are retained, not hidden. This is not a lossless-delivery or latency benchmark.

## What can now be claimed

A successful retained run can say **`VERIFIED_IN_DISPOSABLE_VM` for synthetic UDP on that exact guest-loopback profile**: an actual Linux TBF queue limited received traffic at two rates, with verified rollback and recovered throughput. This is stronger than the previous simulated success fixtures and unsupported-host-kernel result.

It cannot claim authenticated customer-device identity, bank-network reachability, complete management safety, TCP/application fairness, physical NIC line rate, ingress policing, sustained production load, a six-BOM discovery result, continuous monitoring or production execution qualification. All production authorization/qualification flags remain false. The scope/receipts are unsigned engineering artifacts; hashes are not authenticated reviewer/device credentials. Offline scopes are replayable inside their window, and no online execution lease/redemption protocol is implemented.

Before real-host enforcement, the remaining device enrollment, authenticated adapter, existing class/filter/firewall policy ownership, full management exclusions, separate change approval, bounded withdrawal semantics, independent acceptance and out-of-band recovery requirements from Guide 87 still stand. The target's intentionally minimal pinned kernel is a laboratory fixture, not a current production-hardening/security baseline.

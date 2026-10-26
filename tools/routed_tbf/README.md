# Routed disposable TBF laboratory

This extends—not rewrites—the [v1 loopback fixture](../disposable_tbf/README.md).
There is **no customer apply API, network-facing authority, privileged host daemon,
router/cloud adapter or production execution grant**.

## Topology (all inside one diskless, externally NIC-less VM)

```text
tx namespace                 gw namespace                  rx namespace
10.77.1.2/s0 <--- veth ---> 10.77.1.1/gi
                            10.77.2.1/ge <--- veth ---> 10.77.2.2/r0
                                  ↑ owned TBF 7e02:
mgmt namespace                    |
10.78.1.2/m0 <--- veth ---> 10.78.1.1/gm (separate UDP management echo)
```

Only IPv4 forwarding in `gw` is enabled. No NAT, NIC, host forwarding, disk,
mount sharing or external sockets. Kernel PCI, loadable modules and netfilter
are disabled; this intentionally bounded fixture is **not** a general firewall,
bridge/tunnel/VRF, physical-device or bank-management inventory.

- `guest.py`: fixed topology, conservative preflight, workload matrix, independent
  guest watchdog and failure injection. The launcher, not a user-provided target
  argument, owns all QEMU flags.
- `probe.c`: guest-only UDP/TCP payload counters, one/four TCP flows, TCP_INFO
  retransmissions, UDP sequence deduplication/loss, timestamped echo latency.
- `acceptance.json`: engineering thresholds selected by the user before measurements.
- `authority.py`: three distinct local Ed25519 roles; tenant/device/bundle/profile
  binding, explicit simulated-reviewer approval, atomic once-only redemption,
  short-lived lease, revocation and signed adapter receipts. This authenticates a
  **local lab adapter**, not a physical device or independent human reviewer.
- `runner.py`, `report.py`: bounded VM lifecycle, live lease checks, deterministic
  gates and serial/source/parent-policy closure. Failed measurements remain failed.
- `build.py`: private reuse of the v1 locked builder; v1 source/evidence unchanged.
- `trust.py`: archive/license-file inventory, environment/build record and external
  signed review comparison. Review remains pending until independently performed.

The lab authority's 0700 directory and 0600 private keys/database must remain in a
private disposable cache, never Git/chat/VM images. The store owner is trusted;
there is no protected custody, secure clock, rollback-resistant ledger or multi-host
PKI. Three local keys model role separation, **not three independent humans**.

Install/use the repository Python environment (Pydantic 2 and cryptography are
required). Run [the operator recipe](../../docs/runbooks/routed-tbf.md).
Native evidence and unresolved results are in [the readiness record](../../docs/readiness-evidence/routed-tbf-2026-10-26.md).

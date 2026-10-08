# Network TLS scanning

CryptoScan can:

- Discover TLS endpoints from `config/network-scan-targets.yaml` and Kubernetes Ingress/Service manifests
- Parse local PEM/CRT material into a certificate inventory
- Validate leaf/issuer linkage, hostname, and expiry
- Extract OCSP and CRL URLs (live fetch stays off unless `CRYPTOSCAN_TLS_LIVE=1`)
- Track each fingerprint's usages (`PEM_FILE`, `TLS_ENDPOINT`, `K8S_SECRET`)
- Schedule targets (`GET /network/due`, `POST /network/run-due`)
- Optionally open a real TLS handshake (`CRYPTOSCAN_TLS_LIVE=1` or the dashboard **Probe host** action)

Live probes stay off by default so CI and tests never phone the internet.

For the versioned, tenant-scoped network inventory contract—including devices,
topology, configuration-hash drift, coverage, risk, monitoring, wireless,
firmware/software, documentation, evidence, and safe discovery—see
[Vendor due diligence and structured network inventory](vendor-network-inventory.md).
The structured inventory is not a claim of complete network visibility; missing
sections remain incomplete or unknown.

```bash
python scripts/run_network_scan.py /path/to/authorized-source-tree
python scripts/run_network_scan.py example.com:443 --live
```

## Scan admission and authorized scope (2026-10)

Every scan the API accepts and every live network probe now passes **one
fail-closed admission decision** (`api/security/scan_admission.py`):

| Condition | Result |
|---|---|
| Emergency stop engaged (control plane) | **409** — nothing is queued |
| Control-plane / policy lookup unavailable | **503** — no scan is accepted (fail-closed, never fail-open) |
| Safe-scan policy refuses the target | **409** with the policy's reason |
| OT estate declared (an enabled onboarding environment of type `ot`) + active request with no declared maintenance window | **409** — active probing needs an **actual, currently-open** window; passive/safe modes remain available |

The decision is enforced at the common enqueue boundary (so every route that
queues a scan inherits it), on the manual trigger, and on the live-probe
endpoints (`/network/discover`, `/network/run-due`, `/network/ssh-scan`).

**Authorized scope for CIDR sweeps.** A declared network scope entry is
*authorization*, not a target list:

- onboarding **never** materializes a CIDR as an enabled TLS probe target —
  only concrete hosts (IP, `host:port`, domain) enter the due-scan rotation,
  stamped `source="onboarding"`;
- `POST /network/discover` checks at **execution time** that the swept CIDR
  sits inside the declared authorized scope (or is a registered single
  host); otherwise **403** `target_outside_authorized_scope`;
- deleting a scope entry **revokes** the targets it materialized (and only
  those — manually registered or discovery-registered targets are spared,
  and a target another still-enabled entry declares stays on).

**OT is derived, never declared by clients.** Requests cannot claim (or
deny) OT status; the gate reads the estate's trusted declarations.

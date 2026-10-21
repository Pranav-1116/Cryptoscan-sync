# Network TLS and durable SSH scanning

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

## Durable SSH host-key and optional KEX scans

`POST /api/v1/network/ssh-scan` accepts up to 256 authorized endpoints, a bounded
`timeout`, `include_kex`, `strict_kex` and optional `known_host_keys`. For example,
under a provisioned bank A session and approved network scope:

```json
{"hosts":["10.21.0.10:22"],"timeout":8,"include_kex":true,"strict_kex":true,"known_host_keys":{}}
```

Initial target/admission checks precede a committed RUNNING job. Admission is
rechecked before each host-key/KEX phase. Successful recording returns `job_id`
and `run_id`; retrieve them with `GET /api/v1/jobs/{job_id}` and
`GET /api/v1/network/runs/{run_id}` or list `/api/v1/network/runs?target_kind=ssh`.
Foreign estate IDs remain 404. A body field cannot grant another estate's scope.

The stored collection declares `protocol=ssh`, `durable=true`,
`coverage=HOST_KEY_AND_OPTIONAL_KEX_ONLY` and
`baseline_source=CALLER_SUPPLIED_UNVERIFIED`. It stores findings, telemetry,
admission decisions and the returned TOFU map. It does not establish trusted
host identity, log into the device, inspect firmware or create TLS evidence.

COMPLETED means the attempt/result was recorded; TIMEOUT/FAILED observations
remain failed in its verdict and telemetry. Initial receipt storage failure
prevents collectors (and may return 500); later collector/ledger/completion
failure gives no durable-success result, rolls back staged success and attempts
a FAILED stamp. Admission errors retain their policy status; other failures
inside the collection boundary return generic 503. A crash can leave RUNNING.
Generic job retry is 409: resubmit the explicit SSH profile through this route.

This is bounded NBOM/CBOM evidence, not SBOM, TechBOM, HBOM or VBOM completeness.
See [durable SSH details](../bank-environment/44-queued-authority-and-durable-ssh.md).

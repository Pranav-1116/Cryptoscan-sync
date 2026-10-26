# 86 — Network traffic, storage capacity and traffic control: step-by-step build

## What you can use now

Open **Network → Traffic & storage**. The existing TLS topology page remains; a new panel adds explicitly scoped resource observations and traffic-control drafts.

| Step | Delivered now | What it does not claim |
|---|---|---|
| 1. Measure traffic | Ordinary-user Linux collector: selected interface receive/transmit bytes, average Mbps, packet/error/drop counter deltas | Not packet sniffing, flow inspection, destinations, top talkers, per-app/user usage, Internet-only usage or entire-network totals |
| 2. Measure storage | Selected directory filesystem total/free/used/available bytes, used percentage and filesystem-device reference | Not physical disk/RAID/SAN/cloud-pool discovery, RAM, disk I/O rates, quota discovery or additive capacity across paths |
| 3. Review control | Retained, evidence-linked egress-limit proposals with a selected interface and explicit Mbps target | **Draft only. No bandwidth limit or firewall rule is applied.** |
| 4. Enforce safely | **Not delivered in this step:** needs a device-specific executor and change-approval/rollback controls | No hidden `tc`, firewall, router or cloud changes; no apply endpoint |

[API](../api-reference/resource-monitoring.md) · [operator runbook](../runbooks/resource-monitoring.md) · [executed engineering evidence](../readiness-evidence/resource-monitoring-2026-10-26.md).

## Why this was the next missing capability

The repository already had network TLS discovery, certificate posture, monitor targets and network inventory. Those do not establish actual bytes/second or available filesystem capacity. This increment adds a separate explicit measurement contract without rewriting the scanners or pretending TLS service discovery measures bandwidth.

The source path is:

```text
existing estate/system → draft exact scope → authorized human approval
                                           ↓ download scope
                          ordinary-user CLI on intended Linux host
                                           ↓ bounded JSON capture
                          original intake + deterministic report
                                           ↓
                    Network page + evidence-linked traffic-limit DRAFT
```

The API never runs the collector. The user/operator runs it on the intended host and imports the capture. The UI guides scope registration, approval, authorization download, capture import and draft creation. Refresh only fetches retained records; it is not an active monitoring daemon or a customer scan.

## What “find network traffic” means in this first step

Select exact interface names such as `eth0` or `lo`; never a subnet, wildcard or arbitrary shell command. The collector reads the fixed Linux `/proc/self/net/dev` interface twice and uses monotonic elapsed time:

```text
receive Mbps  = (second.rx_bytes - first.rx_bytes) × 8 / seconds / 1,000,000
transmit Mbps = (second.tx_bytes - first.tx_bytes) × 8 / seconds / 1,000,000
```

These are average **interface counter rates**, not guaranteed physical wire throughput or peak rates. Mbps is decimal; the storage UI uses approximate binary GiB. Packet/error/drop values are differences within the same interval, not lifetime totals. Driver drop/error counters do not prove end-to-end packet loss.

- A valid unchanged counter pair means **zero measured traffic**.
- Missing/denied/invalid inputs mean **unknown**, not zero.
- Any counter decrease means `COUNTER_RESET`; changed interface index means `IDENTITY_CHANGED`. All rates for that input remain unknown rather than producing negative traffic or guessing wraparound.
- Boot, network namespace and mount namespace must remain unchanged during capture; otherwise capture is refused. Namespace inode/boot fields are context, not physical-host attestation. Interface deletion/recreation that reuses the same index without detectable counter regression is not independently ruled out.
- A container sees its own namespace/cgroup/filesystem context, not automatically the host or whole bank. Multiple/veth/loopback interfaces can count the same underlying traffic; do not sum them as unique Internet bytes.
- Link speed/capacity and traffic classification remain unknown; no utilization percentage is invented.

For per-IP/app/top-talker analysis, the next measurement adapter should ingest explicitly authorized NetFlow/IPFIX/sFlow, firewall counters or suitably scoped connection/eBPF metadata. That is not implemented by this byte-counter collector, and packet payload collection is not implicitly authorized.

## What “how much storage is present” means

The operator explicitly chooses existing canonical directory paths. The collector opens each directory without following symlinks and calls `fstatvfs` on that descriptor. It does not walk or read file contents.

```text
total bytes               = filesystem blocks × fragment size
free bytes                = free blocks × fragment size
available to collector    = max(available blocks, 0) × fragment size
used bytes                = total − free
reserved free bytes       = free − available
used percent              = used / total × 100, only if total > 0
```

Available space can be lower than free space because of reservations/permissions. Filesystem reports do not necessarily represent all application/project quotas or a physical storage pool. A container overlay can describe a shared backing filesystem. `/`, `/home` and `/data` can all refer to one filesystem; **the product does not add these rows**. The device reference is a scoped hint, not a permanent physical disk identity.

A missing/denied/symlink/invalid directory is retained as a gap, not `0 GB`. A zero-sized measured filesystem has unknown used percentage, not a fabricated 0% utilization. Choose approved local filesystem paths: OS/filesystem calls can stall on remote or unhealthy mounts; count/byte bounds are not a hard syscall execution-time or availability guarantee.

## How traffic control will work

Today, an authorized user can propose an **egress** limit, in explicit decimal Mbps, for an approved interface from a capture no older than five minutes. The server pins the original capture/revision hashes and records whether that one observed sample exceeds the proposed limit.

The proposal always says:

- `state=DRAFT_REQUIRES_DEVICE_ADAPTER_AND_CHANGE_APPROVAL`;
- `applied=false`, `enforcement_supported=false`;
- management-path safety, link-capacity verification and rollback verification are false.

A draft is not a queue entry, firewall authorization or simulation of application impact. The UI says **Save draft limit (not apply)**. The system neither emits runnable traffic-control commands nor invokes privileged tools. There is no `/apply` endpoint.

### Required next enforcement decision

Choose the actual enforcement platform before implementation:

1. **Linux server/gateway:** interface-bound egress shaping through a narrowly privileged local executor; enrolled host identity; explicit management/control-plane exclusions; current qdisc conflict checks; bounded duration, rollback and audit.
2. **Router/firewall/appliance:** vendor-specific read/write API with explicit device/interface identity, staged change, management-access safeguards and configuration rollback.
3. **Cloud network:** provider-specific supported controls. Firewall/security-group rules are not interchangeable with bandwidth shaping; unsupported rate limits must remain unsupported.

Ingress limiting, per-flow fairness, blocking IPs, app quotas and traffic prioritization are different operations and need their own semantics and approval. Do not treat an egress draft as permission for those actions. No credentials or private keys should be sent through chat.

## Authorization and retained truth

Scopes bind an existing selected-estate system/environment, operator host label, up to 16 exact interfaces, up to 16 directory paths, a 1–30 second sampling interval and at most a one-hour authorization window. Human `assurance.manage` creates/imports/proposes; current `assurance.trust` approves/revokes. Each source must return exactly one ordered disposition. Scope revocation serializes against new imports/proposals; historical evidence remains inspectable.

A capture has an explicit original approval record commitment and public nonce. These prevent accidental/mismatched binding; **they are not a signature or host authentication secret**. The host label is operator-declared. A permitted uploader can fabricate an imported return; the product does not certify that the bytes came from the intended physical machine. `producer_authenticity_verified=false`, `provenance=IMPORTED`, complete coverage false and no packet/configuration-change claims remain fixed. Future enforcement must not use these unsigned imports as sufficient enrolled-device execution authority.

The existing append-only assurance store retains captures, derived reports and drafts with transactional audits. GET recomputes reports/drafts from original typed capture data; a changed derived value fails even if its local revision hash is resealed. The controlled-production adapter gate remains closed. No new database/service/scheduler or production-monitoring SLA was introduced.

## Boundaries of this delivery

Implemented and tested: Linux read-only CLI, strict contracts/schemas, approval/intake/report APIs, current Network-page UI, traffic-limit drafts, error/reset semantics, actual sandbox measurement, tenant isolation, audit rollback and PostgreSQL races.

Not implemented: 24/7 collection scheduling, per-flow/app inspection, Windows/router/cloud resource collectors, physical storage inventory, automatic alerts, quota deletion/cleanup, actual network enforcement, rollback qualification, actual customer estate measurements or bank acceptance. This is usable step-one/two functionality, not a claim that every network-management feature is finished.

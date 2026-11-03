# 181 — Security Control Integration

**Status:** built in this guide.
**Layer:** `services/cbom/cbom/security_controls/` (imported as `cbom.security_controls`).
**Harness:** `scripts/cbom_security_controls.py` — 14 points, `SC-01 … SC-14`.
**Artifacts:** `docs/bank-environment/181-security-controls.{json,md}`.
**Positioning sentence (use verbatim):**

> CryptoScan integrates with the bank's existing network and security controls to build an
> evidence-backed cryptographic and security estate model.

This document is the specification the layer is built against, and the record of what the
build decided where the specification left a choice. The probes that hold it are
`SC-01 … SC-14` in `scripts/cbom_security_controls.py`.

---

## 1. Where the capability sits

CryptoScan is a **read-only cryptographic intelligence and correlation layer** *over* the
bank's existing network and security controls. The bank already owns the enforcing devices;
CryptoScan owns the evidence, the identity and the correlation across them.

| CryptoScan **integrates with** | CryptoScan **is not** |
| --- | --- |
| Firewalls, IDS, IPS, WAF | a firewall |
| Rate limiters, API gateways | an IPS |
| Load balancers, VPN gateways | a rate limiter |
| SIEM, PKI/CA, HSM, KMS | a policy engine that pushes rules |
| Network devices and segments | an agent on the data path |

Concretely, and this is enforced in code rather than promised in prose:

* every collector declares only **read** operations (`GET`, `SHOW`, `SHOW_RUNNING`, `LIST`,
  `EXPORT_CONFIG`, `QUERY`, `TAIL_EVENTS`, `READ_CONFIG_FILE`, `PROBE_TLS`, `PCAP_READ`,
  `SYSLOG_READ`, `API_GET`, `CLI_SHOW`); a spec that names a mutating operation
  (`POST`, `PUT`, `PATCH`, `DELETE`, `SET`, `CONFIG`, `RELOAD`, `RESTART`, `PUSH_POLICY`,
  `BLOCK`, `CREATE`, `UPDATE`, `WRITE`) is refused when the adapter is registered, so the
  refusal happens at import time rather than at the moment someone calls it;
* no collector class exposes a write, apply, push, block or reload method at all — the
  contract has six verbs and none of them changes a device;
* where a control can only be read through an API that *also* offers writes, the adapter
  records the read-only subset and the harness asserts the mutating half is absent from the
  declared capability surface.

The single architecture constraint:

```
Vendor Adapter → Common Collector Contract → Normalized Evidence → Canonical Asset Identity → Digital Twin
```

Every vendor is the same shape. A vendor is a *row of data*, not a new architecture: adding
Fortinet, Palo Alto, Check Point, F5, AVI, NGINX, HAProxy, Kong, Envoy, Snort, Suricata,
StrongSwan, Splunk or Sentinel changes a dialect description, not a class hierarchy.

## 2. What is collected, per control

| Control | We collect | We must **not** do |
| --- | --- | --- |
| **Firewall** | rules (allow/deny), zones, interfaces, VPN config, TLS inspection config, address/service objects, policy versions | modify or push a rule; open or close a port; change NAT; act as the packet filter |
| **IDS** | alerts, signature ids and revisions, protocol metadata, event timestamps, source/destination metadata, flow metadata | capture payloads; store HTTP bodies; decrypt traffic; alert instead of the bank's IDS |
| **IPS** | block events, signature/policy ids, rule actions, event timestamps, flow metadata | block anything; tune or disable a signature; sit inline |
| **WAF** | policies, TLS settings, certificates presented, routes behind the WAF, security events | change a policy; read request bodies; store cookies or authorization headers |
| **Rate limiter** | configured limits per policy, API/route mappings, violations (expected vs configured), whether a policy is attached to a target API | enforce a limit; throttle traffic; raise a quota |
| **Load balancer** | VIPs, pools, backends, TLS termination and re-encryption, certificates, cipher suites, protocol profiles | change a pool member; drain or enable a node; rebalance |
| **API gateway** | APIs and routes, TLS and mTLS, certificates, authN/authZ policy *presence*, security events | add or revoke a route; change mTLS trust; issue a token |
| **VPN** | tunnels, IKE version, encryption and hash algorithms, DH group, PFS, certificates, peers | bring a tunnel up or down; rotate a PSK; change a proposal |
| **HSM** | model, firmware, capability flags, partition list, **key metadata** (label, algorithm, size, usage, state) | read, export, wrap, unwrap or generate **key material**; sign anything |
| **KMS** | **key metadata** (id, algorithm, size, usage, state, rotation policy), key policy *presence* | decrypt, encrypt, export or escrow **key material** |
| **SIEM** | security events, correlation references (rule id, event id, investigation id) | write to the SIEM; suppress a correlation; run a response action |
| **PKI / CA** | issued certificates, algorithms, key sizes, validity, chain, revocation state | issue, revoke or renew a certificate; obtain a **private key** |
| **Network devices** | interfaces, routes, ACLs, VPN and TLS parameters, SSH crypto configuration | change an interface, route or ACL; log in with a shared credential |

### Rate-limiter auditing — the three cases that must be distinguishable

These are a capability class, not an example. Each of the following is a *different finding*,
with a different evidence record and a different fact class:

1. **NOT_CONFIGURED** — an API is exposed and no rate-limit policy exists for it. The
   finding is derived from the gateway's route table (`CONFIGURED` evidence of the route,
   `OBSERVED` evidence that traffic reached it), and it is never merged with "we could not
   read the limiter".
2. **OVER_LIMIT** — observed request volume exceeds the configured limit. Two numbers are
   printed side by side, `expected` (configured) and `observed`, and the finding keeps both
   fact classes so the configured number is not mistaken for a measurement.
3. **POLICY_NOT_ATTACHED** — a policy exists, is enabled, and is attached to nothing (or to
   a route that no longer exists). This is the case that a "policy inventory" alone hides:
   the control reports coverage, the audit reports an orphan.

### IDS / IPS correlation

An IDS alert is only useful to a cryptographic estate if it can be turned into a question
about crypto. The layer must answer, for every event:

> **What cryptographic assets and critical systems are involved in this network security
> event?**

and the path it must be able to draw, hop by hop, with evidence and a basis at each hop, is:

```
source IP → host → process → API → crypto library (OpenSSL) → HSM
```

A hop that cannot be resolved is *named* as unresolved. It is never silently skipped and
never guessed from a name — the same rule the NBOM applies to `10.10.10.20:443`.

## 3. What CryptoScan must **not** collect

Hard prohibition. These values are never read into a record, never written to an artifact and
never logged. The redaction guard refuses them by field name *and* by content shape (PEM
private keys, bearer tokens, `Authorization:` headers, card-number-shaped strings), and the
harness asserts a sentinel of each kind does not survive a collection cycle:

* private keys
* HSM key material
* passwords
* API secrets
* session tokens
* customer payloads
* HTTP request/response bodies
* decrypted traffic
* payment / card data
* credentials
* cookies
* authorization headers

For network traffic the layer keeps **metadata only**: TLS version, cipher suite, key
exchange, certificate fingerprint, SNI, ALPN, source/destination address and port, timing,
protocol and flow metadata. This is the same privacy contract the passive NBOM observation
path already carries (`cbom/passive_observation.py`), stated again here because this layer
sees firewalls and gateways, where the temptation to store a body is greatest.

When a prohibited field is encountered, the record keeps a **redaction marker** — the field
name, the evidence id and the count — because "we refused to read this" is itself evidence,
and the reviewer must be able to see that the redaction happened rather than infer it from
an absence.

## 4. Three facts that never merge

Wherever a control is described, these stay separate, in the same record, with different
evidence ids:

| Fact | Question it answers | Typical basis |
| --- | --- | --- |
| `CONFIGURED` | what the control *says* it does | `config-parse`, `api-poll`, `agent-inventory` |
| `OBSERVED` | what the network *saw* | `passive-capture`, `packet-capture`, `sni-header` |
| `RUNTIME_OBSERVED` | what the application *did* | `runtime-probe`, `process-trace` |

The full evidence vocabulary is the existing one and is not extended here:
`CONFIGURED, OBSERVED, RUNTIME_OBSERVED, STATIC_OBSERVED, NETWORK_OBSERVED, IMPORTED,
VENDOR_DECLARED, INFERRED, UNKNOWN` (`cbom.techbom`).

A finding may carry more than one fact class — a rate-limit breach is `CONFIGURED` (the
limit) plus `OBSERVED` (the volume) — but it may never *collapse* them into one verdict, and
a claim may never be stronger than its evidence. A rate limit with no traffic sample is
`CONFIGURED` only and says so.

## 5. Every relationship carries evidence

No relationship is emitted without an evidence id, and it lands in the Digital Twin / NBOM
dependency model with the same edge record shape as the rest of the platform:

```
FW-001  ALLOWS  INTERNET → PAYMENTS-API  TCP/443  evidence=EVID-92821
```

Rules the projection obeys:

* the relation must already exist in `cbom.techbom.RELATIONS`, and the source/target kinds
  must be legal for it (`check_types`); an adapter cannot invent a relation name, and a
  pairing that no relation permits is **refused by name** rather than drawn;
* the asset identity is canonical — `KIND:name:environment` — so the firewall row
  `INTERNET` and the segment row `INTERNET` are the same node, and `PAYMENTS-API` is a
  `SERVICE`, not a string;
* evidence ids are deterministic (`EVID-<CONTROL>-<digest12>`), so re-reading a device on a
  different day produces the same id for the same fact and a diff means a change;
* an edge whose basis cannot support it (a config file claiming `TERMINATES_TLS` without an
  observation floor, a name match used as a topology) is refused with the reason.

## 6. Build decisions

Choices the specification did not fix, recorded so the next guide does not relitigate them:

1. **The layer lives inside the CBOM service** — `services/cbom/cbom/security_controls/` —
   because the asset vocabulary, the relation table, the confidence model and the estate
   schema all live in `cbom.techbom`. A second copy of the vocabulary in a new top-level
   service would be the beginning of a second graph.
2. **A vendor is a row, not a module.** Each control package has `base.py` (the type's
   normalization and read-only surface) and `vendors.py` (the vendor dialect table). The
   requested per-vendor file layout (`fortigate.py`, `paloalto.py`, …) was collapsed into
   `vendors.py` on purpose: twenty near-identical modules *is* "a different architecture per
   vendor", which is the one thing the specification forbids.
3. **The adapters are offline-testable.** A collector is constructed with a *feed* (the
   normalized answers a device's read-only API or config export produced) instead of doing
   I/O inside the contract. That is what lets the harness prove the privacy and evidence
   rules hermetically, and it keeps every network call in one place when the live adapters
   land.
4. **Refusals are data.** An asset or an edge the model cannot accept is returned in
   `refusals` with a code and a reason, and the run still succeeds. Silence is the failure
   mode this layer exists to remove.
5. **`NOT_CONFIGURED` is a finding; `UNKNOWN` is a coverage gap.** They are separate finding
   states, because one is a decision the bank made and the other is a device we could not
   read.

## 7. What is not built yet (honest gaps)

* **No live device drivers.** The feeds in this guide are recorded fixtures; the read-only
  client for each vendor (`GET /api/v2/cmdb/firewall/policy` and friends) is described in
  `vendors.py` but not implemented. Nothing in the contract changes when it is.
* **No persistence.** Findings and evidence are returned as documents; a table for them is a
  separate guide, and it must not become a second source of truth for the estate.
* **HSM, KMS, PKI and the passive network path are *named*, not re-collected.** Each already
  has a read-only collector in the platform (`cbom/hsm_pkcs11.py`, `cbom/kms_collectors.py` +
  `cbom/kmip.py`, `cbom/certificate_chain.py`, `cbom/nbom_graph.py`). The registry returns
  `CONTROL_DEFERRED` with the path that owns it, so a reviewer can see the coverage instead of
  a gap dressed as an empty list. This layer's job for those four is to correlate what they
  produce, not to speak to the device a second time.
* **No HTTP route yet.** The layer is a library plus a harness. Guides 178–180 gave the
  dependency graph a router; this one deliberately does not, because the first version of a
  control-ingest endpoint is also the first version of an unauthenticated write path into the
  estate. The route lands with the live drivers and their authentication, not before.
* **Correlation is bounded by the inventories it is given.** The `source IP → host →
  process → library → HSM` path resolves only as far as the asset inventory, the process
  tracing and the key inventory already reach; every unresolved hop is reported, but a hop
  the platform has never collected stays unresolved until it does.

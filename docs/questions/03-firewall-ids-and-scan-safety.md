# 03 — Firewall, IDS/IPS, rate limits and scan safety

[FAQ index](README.md) · Questions Q025–Q036.

## Q025. Does CryptoScan manage the bank's firewall, IDS or IPS?

No generic firewall/IDS/IPS policy-management capability is established by the current supported deployment. CryptoScan is not an inline security appliance and does not replace those bank controls.

The bank network/security teams own rules, sensor policy, alert handling and approved exceptions. CryptoScan supplies the scoped collection requirements, relevant application/worker evidence and limits. Do not give it firewall administration credentials or assume it opens ports, suppresses alerts or blocks attackers automatically.

## Q026. What firewall rules are needed for an on-premises installation?

Use a reviewed site-specific flow matrix. The current reference includes:

| Source → destination | Example/reference flow | Review requirement |
|---|---|---|
| Approved workstation → ingress | HTTPS 443 | Internal DNS, valid certificate, authenticated access |
| Ingress → frontend | Private service port 3003 | No public node-port assumption |
| Frontend → API | Private service port 8010 | Same-origin proxy; restrict direct untrusted API access |
| API/worker → PostgreSQL | Bank-assigned TLS port, commonly 5432 | Approved CA/hostname and database identities |
| API/worker → Redis | Bank-assigned TLS port | `rediss://`, approved CA and ACL roles; do not assume 6380 everywhere |
| Approved nodes/runtime → private registry | Approved HTTPS endpoint | Bank registry trust and image access |
| Nodes/workloads → required DNS/time/management | Site-specific | Exact required destinations only |
| Isolated source parser → network | **None** | Verify actual launcher/runtime enforcement |

These are deployment flows, not permission to scan bank targets. Default-deny and explicit allowlists should be enforced by bank infrastructure; exact rules require architecture/CNI/runtime review.

## Q027. Should the bank open the whole network or disable IDS for scans?

No. Never request “allow all,” broad `any-any` rules or blanket IDS/IPS suppression as the default. Agree exact sources, destinations, ports, operations, window, traffic budget and rollback/stop owner.

For a separately qualified active-probe pilot, SOC may choose a narrowly documented tuning rule or scheduled alert handling. That is the bank's decision; it must not hide unrelated attacks. Keep monitoring active and retain the approved exception and expiry. Offline collection may eliminate the need for a remote acquisition flow.

## Q028. What should happen if IDS/IPS raises an alert during a scan?

Use the agreed stop/escalation procedure. Correlate the target/job/window, source and destination, observed request, sensor event and bank change reference. Preserve available evidence and determine whether the activity was authorized, excessive, misrouted or unrelated.

Do not label every alert a false positive, attempt evasion, retry through another route or disable inspection. Resume only after the authorized owner resolves the issue and any required scope/change approval is updated. Integration into a SIEM or alert channel must itself be available and qualified; this FAQ does not add a connector.

## Q029. What API rate limits exist in the code?

Current `DEFAULT_RULES` in the API rate-limit middleware are:

| Endpoint class | Requests | Window |
|---|---:|---:|
| Login | 5 | 60 seconds |
| Registration | 10 | 3,600 seconds |
| Scan submission | 100 | 60 seconds |
| Host/universal collection writes | 10 | 60 seconds |
| Host/universal collection reads | 60 | 60 seconds |
| Other API | 600 | 60 seconds |

These are **code defaults per resolved identity bucket/endpoint class**, not a capacity promise, scan speed recommendation or site configuration approval. Classification is path/method based. Exceeded/closed decisions return HTTP 429 with rate-limit and retry information.

The identity resolver uses API-key header hashing, a validated session identity when available, otherwise the trusted client-IP path. Do not assume every bucket is an independently authenticated person or that the login rule is an unconditional global/per-IP brute-force guarantee. Ingress controls and adversarial identity/header tests are still needed.

## Q030. Are rate limits shared across API replicas, and what if Redis fails?

The middleware has an in-process sliding-window path for development and a Redis-backed fixed-window path. Production configures fail-closed behavior: unavailable shared limiting must not silently become independent per-process quotas.

A shared Redis connection alone does not establish correctly aligned multi-host enforcement or abuse resistance. Validate actual replica/clock/proxy/failure behavior and boundary bursts; the shared implementation uses its supplied clock for window keys. Keep a reviewed ingress/WAF limiter as another layer. Do not infer qualified multi-replica operation from this middleware or increase replica counts without testing.

## Q031. Is the API rate limit the same as the traffic sent to bank targets?

No. They are separate controls:

- API request limiting constrains calls to CryptoScan.
- Admission/queue budgets constrain accepted work and concurrency under the relevant workflow.
- A collector needs its own input/byte/fact/time/connection/probe limits.
- Infrastructure limits constrain CPU, memory, PIDs, disk and network paths.

One API request could initiate substantial work; 100 submissions/minute does not authorize 100 target probes/minute. Host metadata collection may perform no network probe at all. Set and demonstrate limits for the exact admitted adapter, not one universal “scan rate.”

## Q032. How does CryptoScan prevent a scan from overloading a server?

Implemented scoped paths use measures such as explicit inputs, byte/fact caps, bounded parsing, expiry, durable execution controls, least privilege and isolated parser resource limits. A controlled source parser is launched with constrained CPU/memory/PIDs and a networkless/read-only boundary.

These measures do not prove zero impact on every host, native API or bank runtime. Windows candidates still have native allocation/latency/cancellation qualification gaps. Agree a representative workload and maximum admitted load, measure production-like resource effects, and stop on service degradation. Do not use example limits as a bank-wide sizing guarantee.

## Q033. How are SSRF, DNS rebinding and lateral movement addressed?

For any network-enabled adapter, independently enforce exact approved destinations, resolution/use binding, redirect behavior, credential separation and network egress policy. A hostname or URL string alone is not a safe destination boundary.

The current controlled source parser is networkless, and the universal offline host contract is not a generic URL/shell executor. That does not qualify every legacy network route. Test prohibited addresses, DNS changes, redirects and metadata endpoints against the exact separately admitted network adapter. No automatic pivot is authorized by discovering another address.

## Q034. Can Kubernetes NetworkPolicy alone isolate the parser?

No. CNI enforcement must actually be present and tested, and a host-daemon-launched parser is not necessarily governed by pod NetworkPolicy. The reference uses a reviewed dedicated worker/daemon boundary and a constrained parser launch; actual networkless execution must be verified there.

The parser must not receive bank credentials, database access, the Docker socket or broad host mounts. Separate Linux host-stage Landlock/seccomp tooling has its own OS/ABI and qualification limits; it is not interchangeable with every container runtime or Windows isolation boundary.

## Q035. What if a malicious user forges proxy headers or floods requests?

The bank must restrict direct API access to the reviewed trusted ingress/proxy path and test Host, origin and forwarded-header handling. Current launch/proxy assumptions make this especially important. Do not trust arbitrary `X-Forwarded-For` as identity or treat CORS as authentication.

Apply perimeter/ingress protections, body/connection/time limits, valid session/role/estate checks, shared limiting and backend budgets. Assess invalid credentials and rotating headers as abuse cases. Application controls reduce risk; they do not replace a DDoS protection service, IDS/IPS or independent security testing.

## Q036. What are mandatory stop conditions during a pilot?

Agree them before execution. Examples: unexpected destination/operation, unauthorized scope, expired authority, sustained target degradation, unacceptable resource growth, isolation failure, secret exposure, evidence-integrity failure, wrong-estate disclosure or SOC-declared incident.

A stop request is not proof that every child/native call has terminated or that remote side effects rolled back. Preserve uncertain state, inspect actual execution and cleanup, and reconcile durable work before retrying. A timeout, cancelled UI request or disconnected browser must not be treated as confirmed safe completion.

### References

[Network zones/reference flows](../BANK-ON-PREMISES-DEPLOYMENT.md#8-network-zones-and-firewall-rules) · [rate-limit implementation/defaults](../../services/api/api/middleware/rate_limit.py) · [middleware wiring](../../services/api/api/main.py) · [controlled surface refusal](../../services/api/api/middleware/controlled_surface.py) · [Linux host-stage isolation](../../services/inventory/inventory/isolation.py)

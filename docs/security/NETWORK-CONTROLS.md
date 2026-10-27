# CryptoScan inside a bank network — IDS, firewalls, proxies, rate limits

For the bank's security-architecture and SOC review. Everything here is derived from the code in this
repository; where a control has not yet been exercised on a real bank network it says so.

## 1. Principle

CryptoScan is a **static-analysis product that runs inside the bank's perimeter and needs no internet**.
Its core work — reading source, bytecode, mobile packages, mainframe members, configs, logs — produces no
network traffic at all. What little traffic exists is east-west, low-volume, from fixed addresses, and looks
like a CI runner plus an internal web application. There is no vendor SaaS, no telemetry, no phone-home
(`docs/security-questionnaire.md`: *Data egress: none*).

## 2. Traffic matrix (what talks to what)

| # | Flow | Protocol / port | Direction | Volume | Needed for | Control |
|---|---|---|---|---|---|---|
| 1 | Worker → source-control (Bitbucket / GitLab / GitHub Enterprise / Azure DevOps) | HTTPS 443 or SSH 22 | outbound, internal | one `git clone --depth` per job; sequential per worker | code scanning | read-only deploy token or SSH key; one allow rule from the worker subnet |
| 2 | Worker → file share / mainframe export (NFS, SMB, FTP/S drop, PDS unload) | as provided | outbound, internal | read once per scan | mainframe / vendor code, runtime logs | read-only mount or drop folder — no reverse connection |
| 3 | API / worker ↔ PostgreSQL, Redis | 5432 / 6379 | internal, same segment | continuous | job queue, findings, audit | 3-tier segmentation; configure DB transport separately; production realtime Redis requires verified TLS/ACLs (edge TLS overlay is insufficient) |
| 4 | Users / CI → API | HTTPS 443 via nginx (`deploy/ha/nginx.conf`) | inbound, internal | interactive + CI webhooks | UI, API, exports | behind the bank's WAF / reverse proxy; SSO |
| 5 | API → identity provider | HTTPS 443 | outbound, internal | at login + JWKS refresh | OIDC / SAML / LDAP | https enforced; JWKS URL restricted to the issuer host (`api/security/oidc.py:_validate_jwks_uri`); **or** `OIDC_JWKS_FILE` = no call at all |
| 6 | API → ITSM / SIEM / SCM status (ServiceNow, Jira, Splunk, Sentinel, GitHub status) | HTTPS 443 | outbound | one call per event | optional connectors | **off unless a token/URL is configured** (`pipeline_runner._post_github` returns with no `GITHUB_TOKEN`); route through the bank proxy |
| 7 | Worker → internal endpoints (TLS posture, live monitor, OT/telecom passive) | TCP 443 / SPAN | outbound, internal | a handful of TLS ClientHellos per target per run; passive taps send nothing | optional live modules | scope-authorised targets only; SSRF guard; ≤ 1 000 pkt/s guardrail; fixed source IP |
| 8 | Anything → internet | — | — | **none** | — | default-deny egress is supported and recommended |

Flows 1–5 are all a static-only pilot needs. Flows 6–7 are opt-in modules.

## 3. Firewall rules for a static-only pilot

```
allow  worker-subnet  ->  scm-host            tcp/443 (or tcp/22)     # git clone
allow  worker-subnet  ->  fileshare-host      nfs/smb                 # mainframe & vendor drops (if used)
allow  app-subnet     ->  db-host             tcp/5432
allow  app-subnet     ->  redis-host          tcp/6379
allow  user-vlan, ci  ->  cryptoscan-nginx    tcp/443
allow  app-subnet     ->  idp-host            tcp/443                 # omit with OIDC_JWKS_FILE
deny   app-subnet     ->  any                 (default)
```

No inbound rule from outside the bank, no outbound rule to the internet.

## 4. IDS / IPS / NDR

* Static scanning is invisible to network sensors — file reads only.
* Flow 1 is byte-for-byte a git client; the SCM already sees hundreds of these from CI.
* Runtime evidence is a **log ingester, not a probe**: ICSF SMF-82, RACDCERT, payShield audit, JSSE debug,
  `openssl s_client`, nginx/Apache/HAProxy `$ssl_cipher`, sshd, AT-TLS `EZD12xxI` are read from files the
  bank exports (`scanner/parsers/runtime_log_parser.py`, `scripts/ingest_runtime_logs.py`). Nothing new
  appears on the wire.
* The optional live modules (flow 7) are the only thing an IDS can see. They send well-formed TLS
  ClientHellos from one known worker IP to explicitly authorised targets. Before enabling them: file the
  scope authorisation, whitelist the worker IP in the IDS with the ticket reference, run one target, review
  the SOC console, then widen.

## 5. Guardrails built into the product

| Guardrail | Where | What it stops |
|---|---|---|
| Target validation, fail-closed | `api/security/target_validation.py` | scanning loopback, link-local, cloud metadata (169.254.169.254), multicast, reserved ranges; filesystem targets outside the allow-listed root |
| Scope & authorisation records | scope/authorisation layer (`cf46280`) | any live scan of a target the bank has not put in scope |
| SSRF guard on JWKS discovery | `api/security/oidc.py` | the IdP URL being used to reach internal hosts |
| Packet-rate guardrail, passive mode | OT / telecom collectors | anything resembling a flood; passive taps send zero packets |
| Rate limiting | `api/middleware/rate_limit.py` — 600 req/min per identity (API key → user → IP), per-route classes | credential stuffing, runaway CI clients; measured: a shared identity is throttled to 429 within seconds (`docs/load-soak.md`) |
| Authentication fail-closed | `AuthMiddleware`, API keys with expiry, JWT | unauthenticated access; a key past expiry is a 401 (fixed and load-tested 2026-09-25) |
| Job queue back-off | `worker/core/job_consumer.py` | hammering a throttling SCM: failed clones retry ≤ `JOB_MAX_REDELIVERIES`, then dead-letter |
| Audit chain | append-only, hash-chained audit log | undetected tampering with the tool's own actions |

## 6. Rate limiting — both directions

*Bank throttling us:* clones are one connection per repository; a 429/reset fails the job with a reason and
it is retried with the attempt counter visible, never in a tight loop. Connector calls are one per event.

*Us protecting the bank:* the API limiter above; capacity measured at ~180 authenticated, database-backed
requests/s per API worker (2 vCPU sandbox) so the bank can size workers behind its load balancer.

## 7. Proxies, TLS inspection, corporate CAs

* No internet ⇒ TLS-inspecting egress proxies are normally not in the path.
* For optional connectors: standard `HTTPS_PROXY` / `NO_PROXY`; mount the bank root CA into the container
  trust store at install.
* Git over SSH bypasses TLS interception entirely; HTTPS with deploy token works through inspecting proxies.

## 8. Data handling

* Repositories are cloned into an ephemeral workspace, scanned and deleted; only findings (file, line,
  algorithm, evidence snippet, dependency edges) persist — never the code.
* Uploaded binaries are tenant-scoped and sealed at rest.
* No secrets are stored from scans: shared-key analysis records **identifiers** (keystore file names,
  aliases, environment-variable names), never values.

## 9. Status

| Item | State |
|---|---|
| Traffic matrix, guardrails, rate limiter, SSRF guards | implemented and unit-tested in this repository |
| Default-deny egress operation | supported by design (air-gap install documented and run once) |
| Behaviour under a specific bank's IDS / WAF | **not yet observed** — first engagement step: review §2 with security architecture, deploy static-only, enable live modules target by target |

## Redis discovery and authority boundary — current increment

Allow only approved TLS data/discovery endpoints. Optional Sentinel uses separate
discovery credentials and hostname-verified TLS on all discovered primaries;
three addresses alone do not establish independent failure domains. Review CA
mounts and ACL commands/prefixes per service: realtime/current-run factory support
does not migrate every queue/rate-limit/health client.

A permitted network path or authorized hostname is not job authority. Before
collection, descriptors reconcile against SQL, current initiating identity is
checked and a QUEUED-only claim commits. SSH stores a RUNNING attempt before
packets and rechecks each host-key/KEX phase, but this is not positive bank scope
grants, distributed connection/QPS reservation or an in-flight kill switch.
See [security/HA qualification](../bank-environment/45-redis-tls-sentinel-qualification.md).

# 01 — Entry into the bank and deployment topology

[Guide index](README.md) · Next: [Collection and access](02-collection-and-access.md)

## 1. The tool enters through an approved installation, not through a scan

A bank normally handles CryptoScan as a security platform procurement and
implementation project. The sequence is:

1. **Sponsor and scope:** application security, cryptographic governance or the
   CISO nominates the pilot systems, owners and purpose.
2. **Third-party/security review:** review source/build provenance, licenses,
   data handling, authentication, network behavior, support access and findings
   retention. Obtain written permission to scan the selected targets.
3. **Bank platform provisioning:** create the approved VM/container environment,
   storage, internal DNS, certificates, secrets and service accounts.
4. **Artifact admission:** transfer an approved release through the bank's
   registry/mirror or controlled offline process. Verify its provenance and
   digests. A locally built tag is not a signed, approved release by itself.
5. **Installation and configuration:** configure data stores and identity;
   migrate the schema; install separately required collector/parser runtimes.
6. **Connectivity approval:** grant only the selected source/API/port paths.
7. **Pilot validation:** prove one real target in each purchased scope before
   expanding. Inventory registration alone is not acceptance evidence.

The bank need not give the vendor direct access to production. Bank staff can
operate the deployment and provide sanitized support bundles. Any vendor
remote-access session is a separately approved, time-limited support process,
not a built-in prerequisite for inventory generation.

## 2. Practical placement

### Pattern A — Dedicated internal deployment

A useful initial pattern is one installation for one customer in the bank's
security-management zone:

```text
Operator workstation -- HTTPS 443 --> bank-controlled reverse proxy
                                           | same-origin /api
                                      React frontend + API
                                           |
                         +-----------------+------------------+
                         |                 |                  |
                    PostgreSQL           Redis          graph service
                         ^                 ^              if deployed
                         |                 |
                         +------ worker ---+
                                  |
                           staged source input
                                  |
                     isolated source-parser runtime
                     no target/network/DB credentials
```

Compose definitions include PostgreSQL, Redis, Neo4j, API, worker, frontend,
nginx and monitoring-related services. These are deployment components, not a
claim that every scanner is a separately deployed network microservice.

Production definitions remove direct host exposure of databases and the API.
The base production overlay exposes HTTP at nginx; add the TLS overlay or an
approved upstream TLS terminator. Do not expose HTTP-only production ingress
just because a Compose file starts successfully.

### Pattern B — Segmented infrastructure

A collector can only observe a zone it can reach. For a payment zone, private
cloud segment or isolated data centre, the bank chooses between:

- narrowly approved routes from the relevant central executor;
- an approved local collector/agent exporting metadata;
- a controlled offline file export imported into the central platform.

This is an architectural choice, **not** a promise that a turnkey distributed
collector is automatically installed in every zone. Hardware event/edge-sync
APIs exist; transport, identity, deployment and vendor-specific collection still
need integration and qualification. A bastion, VPN or privileged remote login
must not be silently introduced by the product team.

### Pattern C — Disconnected / air-gapped deployment

Prepare and inspect images, dependency artifacts, parser image and source on a
connected build host. Transfer through the bank's approved channel, verify
checksums/provenance, and use the bank's internal registry or preloaded images.

Build/package installation is separate from scanning. `npm ci`, Python package
installation and online advisory/feed lookups are not offline operations unless
backed by approved mirrors. Runtime egress can also come from cloud APIs,
revocation checks, image pulls, external feeds, notifications or configured OTLP
exporters. Disable or internally route each one intentionally; do not claim
blanket “no outbound traffic” from a product label.

See the [air-gap runbook](../admin-guide/air-gap-install.md), but apply the newer
[source-parser prerequisites](../dev/scanner-isolation.md) and current image
inventory rather than treating older boot examples as complete production proof.

## 3. Firewall and data-flow worksheet

The bank must approve the **actual executing process**, not just “the scanner”.

| Initiator | Destination | Typical flow | Why / limit |
|---|---|---|---|
| Operator browser | Internal HTTPS ingress | 443 | Console, authenticated APIs, SSE; browser never needs direct DB access |
| Reverse proxy | API / static frontend | Internal service ports | Keep private; configure trusted proxy/host/origin settings |
| API and worker | PostgreSQL / Redis | Deployment-defined, commonly 5432 / 6379 | Persistence and dispatch; not exposed to user networks |
| Worker clone stage | Approved Git service | HTTPS 443 or separately reviewed transport | Clone selected repository/revision, not all projects |
| Network executor: API, scheduled worker or collector | Approved listeners | Explicit ports such as 443 / 8443 | TLS/protocol observations; connection attempts are active traffic |
| Cloud executor | Approved cloud endpoints | Usually TLS 443 | Read permitted control-plane metadata, not unrestricted account access |
| Approved hardware collector | Device management plane | Chosen management API / SNMPv3 / reviewed read-only channel | Only the implemented, qualified collector path; no universal device reach |
| Edge collector | Internal ingestion API | HTTPS | Metadata/events and heartbeat with scoped credentials |
| Isolated source parser | None | No network | Admitted read-only source and bounded local output only |

DNS, time synchronization, trust stores and certificate validation also need
planning. A blocked service yields an explicit coverage/connection failure; the
right response is to investigate the approved route, not to disable security
validation or expand access to the whole estate.

## 4. Configuration and startup gates

Inspect these current files together:

- [Base Compose](../../docker-compose.yml),
  [production overlay](../../docker-compose.prod.yml),
  [TLS overlay](../../docker-compose.tls.yml).
- [Production environment template](../../.env.production.example).
- [Isolated parser deployment contract](../dev/scanner-isolation.md).

Before any production start, the bank must supply, at minimum, the required
strong database/application/signing secrets, administrator password hash,
explicit allowed origins/hosts, PostgreSQL configuration and trusted HTTPS
certificate material. Do not commit these values. Identity-provider setup and
MFA/user provisioning must be tested with the bank, not assumed from an OIDC
feature flag.

A **qualified operator** can use the following configuration-inspection command
after secret injection; it is not a complete installation script:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f docker-compose.tls.yml config --quiet
```

Do not print resolved Compose configuration into an unrestricted ticket: it can
contain injected secrets. Migration execution uses the migration service; verify
its exit status and current Alembic head before starting collectors. This branch
includes receipt migrations 0096 and 0097, but operators should inspect the real
head rather than hard-code a migration count from a historical document.

### Important current blocker: production source-parser provisioning

The stock Compose worker is **not a fully provisioned isolated source scanner**.
Production requires container mode and a preloaded immutable scanner image
reference. The operator must also provide a reviewed runtime/CLI and staging
storage visible at the same canonical path to worker and daemon. The stock
private tmpfs does not accomplish that, and the worker image does not bundle
the required Docker CLI. Missing prerequisites fail closed.

Do not “fix” this by enabling privileged mode or mounting an ordinary rootful
host Docker socket into the stock worker. Follow the isolation contract and
retain positive/negative runtime evidence. Other collectors are not made
isolated merely because the source parser has its own container.

## 5. Bank-owned responsibility split

| Bank team | Concrete responsibility |
|---|---|
| Platform / infrastructure | Hosting, private service networking, storage, backups, certificates, recovery |
| IAM | Identity provider, service accounts, roles, revocation, MFA and audit ownership |
| Network / SOC | Approved scope, firewall rules, scan windows, traffic limits and stop procedure |
| Application owners | Correct repository/build/revision, business linkage and interpretation |
| Cloud / HSM owners | Least-privilege metadata access; no key-export or admin privileges for convenience |
| Security governance | Policy packs, retention, exception approvals and acceptance decision |
| Product implementation team | Configure supported paths, explain gaps, test integrations, provide evidence |

A non-production pilot is the first validation gate. No fixed VM sizing,
estate-wide duration, HA/DR guarantee or bank deployment success is inferred
from the existence of these deployment files.

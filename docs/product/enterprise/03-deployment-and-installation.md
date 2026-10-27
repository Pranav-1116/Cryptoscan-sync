# Deployment and installation guide

This page explains how to choose a topology, install it, configure the
runtime, validate health, and move toward a controlled production deployment.
The command-level authority remains the [installation guide](../../admin-guide/installation.md),
[production guide](../../admin-guide/production.md), and deployment manifests.

## 1. Deployment models

| Model | Use | Data boundary | Operational responsibility |
|---|---|---|---|
| Local development | Explore UI, run unit tests, develop connectors | Local machine and local database | Developer |
| Docker Compose development | Exercise API, worker, dashboard, database, queue, and graph together | Compose network and mounted volumes | Development team |
| Dedicated production host | Single-customer controlled deployment | Customer-controlled host, database, queue, and edge | Customer/operator |
| Staging | Run migration, smoke, backup, and release checks before production | Isolated staging data and credentials | Release/operations team |
| Air-gapped or restricted network | Operate without uncontrolled outbound access | Customer network; imported feeds and pinned identity metadata | Customer security and operator |
| Kubernetes or managed infrastructure | Customer-specific orchestration and scaling | Must be designed and validated per environment | Customer platform team plus Vendor guidance |

The repository contains deployment material for several models, but the
presence of a manifest does not prove that the customer's topology, backups,
identity, monitoring, or disaster recovery are complete.

## 2. Prerequisites

Confirm before installation:

- supported Python and Node versions for the selected development path;
- Docker/Compose or an approved runtime platform;
- PostgreSQL for production-like use, with SQLite limited to development;
- Redis when queue or cross-process event behavior is required;
- optional Neo4j when graph persistence is enabled;
- persistent storage for database, evidence, reports, backups, and logs;
- TLS termination and an explicit dashboard/API origin;
- secrets manager or protected secret files;
- outbound and inbound network paths for configured integrations;
- a time-synchronization source; and
- named owner, security contact, and incident escalation route.

## 3. Development installation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
bash scripts/run_stack.sh
```

The exact development command may vary by environment; use the repository
scripts and inspect their output. Development credentials and wildcard CORS
are not production settings. Never carry `admin / cryptoscan`, demo secrets,
SQLite, or `CORS_ORIGINS=*` into a production deployment.

## 4. Production configuration

Use `.env.production.example` as a field list, not as a secret source. Set:

- a strong `SECRET_KEY` and administrator password hash;
- database, graph, and queue credentials;
- a real `CORS_ORIGINS` allowlist;
- webhook secrets and API keys in a secret manager;
- TLS certificates and private keys outside the repository;
- production environment flags;
- explicit identity provider configuration if SSO is used;
- artifact encryption key material where artifact sealing is enabled; and
- backup, log, and evidence retention settings.

The production guard is expected to reject demo defaults, unsafe SQLite use,
and wildcard origins. Treat a guard failure as a deployment failure, not as a
warning to suppress.

## 5. Startup sequence

A controlled deployment should start in this order:

1. provision protected storage and secrets;
2. start the database and verify connectivity;
3. apply migrations and confirm the expected head;
4. start Redis/queue and optional graph storage;
5. start API/control-plane processes;
6. start worker and monitor processes;
7. start the dashboard and edge proxy;
8. run health and readiness checks;
9. create or federate the first operator account;
10. configure backup and alert destinations; and
11. perform a small authorized smoke scan before onboarding more sources.

## 6. Health and readiness

Use the health endpoints documented by the running API, including `/health`,
`/ready`, `/healthz`, or `/readyz` where the selected deployment exposes them.
A process health response proves that a process answered; readiness must also
prove the dependencies required for that role are available.

Record at minimum:

- build/version and commit;
- migration head;
- database and queue status;
- worker liveness;
- graph status if enabled;
- evidence storage status;
- configuration guard result;
- identity provider status; and
- timestamp and operator.

## 7. Network boundary

The preferred production layout is:

```text
Users / CI / approved connectors
              |
        TLS edge / proxy
              |
        API and dashboard
          |          |
       worker      monitor
          |          |
      PostgreSQL  Redis
          |
      optional graph / object storage
```

Do not publish PostgreSQL, Redis, or graph ports to untrusted networks. Permit
only the traffic required for configured sources and integrations. For OT and
restricted networks, use the [network controls](../../security/NETWORK-CONTROLS.md)
and [air-gap guide](../../admin-guide/air-gap-install.md).

## 8. Installation acceptance

A deployment is ready for pilot use only after:

- production guards pass;
- TLS and origin restrictions are tested;
- admin and operator access are configured;
- a least-privilege API key path works;
- a safe test scan creates verifiable evidence;
- backups produce integrity manifests;
- restore is tested in an isolated environment;
- logs and metrics reach the approved destination;
- alert and support contacts are tested; and
- the owner records what remains SKIP, BLOCKED, or environment-dependent.

## Execution/replay rollout requirements (2026-10-21)

Follow the [coordinated upgrade runbook](../../runbooks/execution-and-replay-upgrade.md)
before production launch. New queued jobs must capture current authority pins;
legacy unpinned jobs need approved resubmission. Inline execution is not a bypass.
RUNNING recovered deliveries do not automatically resume under the QUEUED-only
claim, so account for unknown effects before creating a new attempt.

Provision named rediss ACL credentials, a mounted approved CA bundle and valid
SANs for all data/discovery endpoints. Edge HTTPS does not configure Redis TLS.
Optional Sentinel covers realtime/current-run factory clients, not every queue,
rate-limit or health client. Template manifests and local lab results do not
establish deployed HA/security or independent failure zones.

## Current-reading update — 2026-10-22

The controlled profile is local-source/v1 with external regional PostgreSQL, verified-TLS Redis, coordinated API/worker/frontend and a networkless digest-pinned parser. Apply the full migration chain through **0105**; the Compose examples below are development/legacy patterns, not site acceptance.

See [current implementation status](../../CURRENT-IMPLEMENTATION-STATUS.md),
[CI/build contract](../../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) and
[operator install/upgrade/recover](../../runbooks/operator-install-upgrade-recover.md).

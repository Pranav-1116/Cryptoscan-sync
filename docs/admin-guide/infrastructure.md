# Infrastructure & Deployment — where each decision lives in the build

This maps the platform's infrastructure/deployment requirements to the
artifacts that implement them. Two rules govern every row:

1. **Cache is never authoritative evidence.** Cached reads are aggregates
   and reference data with bounded staleness (`api/cache.py`,
   `api/cache_policy.py`); evidence status, certificate expiration, asset
   freshness, risk findings, user permissions and Digital Twin state are
   always read from the record (`cache_policy.AUTHORITATIVE` — enforced,
   tested).
2. **CryptoScan installs in an isolated bank network.** Nothing requires a
   permanent external connection: the dashboard ships in the local nginx
   image, live probing is off by default, and every external artifact is
   staged and verified up front (`scripts/offline_bundle.py`,
   [air-gap-install.md](air-gap-install.md)).

## Technologies

| Technology | Priority | Where it lives in the build |
|---|---|---|
| Load balancer | High at scale | `k8s/app/45-availability.yaml` (PDBs) + any L4/L7 LB in front of `21-api-service`; compose HA pair in `deploy/ha/` |
| Reverse proxy | Critical | `infra/nginx/sites/cryptoscan.conf`, `.docker/nginx/nginx.conf` (TLS, security headers), `deploy/ha/nginx.conf` |
| API gateway | High | Reverse proxy + application controls (`api/middleware/`: auth, rate limit, security headers) — a dedicated gateway is introduced only if the bank's estate demands it |
| CDN | Low (on-prem) / Medium (SaaS) | `deploy/cdn/cache-policy.json` + README — only when content distribution is real |
| Redis caching | High | `api/cache.py` + `api/cache_policy.py` (dashboard aggregates, category summaries, policy definitions, vendor reference, asset summaries, UI config); `api/events/redis_backend.py` for event transport. **Never authoritative evidence** |
| Message queue | Critical | Durable DB-backed job queue (`binary_intelligence/durable_queue.py` with leases, bounded retries, dead-letter) + worker pool (`services/worker/`) |
| Object storage | Critical | `db/storage/cas.py` `FileObjectStore` on a bank-approved mount, `DbObjectStore` for metadata-only deployments (storage optimization batch) |
| Containerization | Critical | `.docker/*` images, `docker-compose.yml` (dev), `docker-compose.prod.yml` (prod profile) |
| Kubernetes | Medium initially / High at scale | `k8s/app/` (namespace, configmap, secrets example, deployments, services, ingress, PVC, availability) |
| Helm | High | `k8s/helm/cryptoscan/` — repeatable install over the same objects; images/tags/replicas/resources come from `values.yaml` |
| NGINX / Envoy | Critical | nginx as above; `deploy/stack/envoy/` for the service-mesh form |
| Autoscaling | Medium–High | `deploy/stack/k8s/25-worker-hpa.yaml` (CPU baseline; queue-depth via the custom-metrics adapter at scale) + chart HPA |
| Network policies | Critical | `k8s/app/45-availability.yaml` (default-deny + explicit allowances) |
| Persistent volumes | Critical | `k8s/app/32-estate-telecom-pvc.yaml`, `k8s/neo4j/persistentvolumeclaim.yaml` |
| Resource quotas | Critical | `k8s/app/46-resource-quota.yaml` (ResourceQuota + LimitRange) — resource exhaustion is a ceiling, not weather |
| Service discovery | Medium | Compose DNS / Kubernetes Services — no external registry calls |
| Secrets manager | Critical | `k8s/app/15-secret.example.yaml` (mounted secrets), `deploy/stack/vault/` (HashiCorp Vault form for banks with one) |
| WAF | Deployment-dependent | Edge concern — terminate at the bank's existing edge; the app enforces its own headers + rate limits regardless |
| TLS / mTLS | Critical | nginx TLS termination; service-to-service inside the cluster per the bank's mesh policy (docs/security/threat-model.md) |
| Infrastructure as Code | High | `k8s/` manifests + `deploy/` profiles + this chart are the source of truth; Ansible/Terraform wrappers per bank standard |
| CI/CD | Critical | `.github/workflows/` (ci, db-migration, docker-build, scanner-tests) + `scripts/operator_release.py` (signed, pinned, provenance-checked releases) |
| Software signing | Critical | `operator_release.py` provenance: `files_sha256`, migration-head pin, attestation verification |
| SBOM for CryptoScan itself | Critical | `make sbom` → `scripts/generate_own_sbom.py` (CycloneDX over Python lock + frontend lock + first-party services) |
| Offline installation | High | [air-gap-install.md](air-gap-install.md) + `make offline-bundle` (`scripts/offline_bundle.py` — manifest + tamper-evident verify) |
| Backup automation | Critical | `scripts/backup_evidence.py`, `deploy/ha/pg-backup/`, `docs/admin-guide/backup-restore.md`, restore drills in `db/storage/restore.py` |
| Blue-green / rolling | High | Rolling updates with `maxUnavailable: 0` (k8s deployments + chart); blue-green for the DB-owning tier per the runbooks |
| Configuration management | Critical | `.env.example` / `.env.production.example` + `api/config/settings.py` (validated settings) |

## What is deliberately NOT in the box

* **A dedicated API gateway product** — the reverse proxy + in-app controls
  cover the requirement; adding a gateway is a deployment choice, not a
  platform dependency.
* **A CDN in on-prem deployments** — banks run the dashboard from the local
  nginx image; `deploy/cdn/` exists for SaaS.
* **A hard dependency on Vault** — the platform reads secrets from mounted
  files/Compose secrets; `deploy/stack/vault/` documents the Vault form for
  banks standardized on it.

## Validation

These contracts are pinned, not just written:

* `services/api/tests/unit/test_cache_policy.py` — the two cache lists and
  the never-stale-authoritative guarantee
* `services/api/tests/security/test_self_sbom.py` — the platform's own SBOM
  covers both lockfiles and every first-party component
* `services/api/tests/security/test_infrastructure_contracts.py` — quotas,
  Helm chart shape, offline bundle completeness/tamper honesty

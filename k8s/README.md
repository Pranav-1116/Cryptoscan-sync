# CryptoScan Kubernetes Manifests

`neo4j/` deploys the optional dependency-graph database.
`app/` deploys the CryptoScan platform itself (API + worker).

## Layout

| File | Purpose |
|---|---|
| `app/00-namespace.yaml` | `cryptoscan` namespace |
| `app/10-configmap.yaml` | non-secret settings (log level, queue key, worker concurrency) |
| `app/15-secret.example.yaml` | template for secrets — copy, fill, `kubectl apply`; never commit the filled copy |
| `app/20-api-deployment.yaml` | API (2 replicas, a rolling update that never dips below the count, liveness `/healthz`, readiness `/readyz`, read-only root, no service-account token) |
| `app/21-api-service.yaml` | ClusterIP service — the API is not exposed outside the cluster |
| `app/30-worker-deployment.yaml` | scan worker (scale `replicas` or `MAX_CONCURRENT_JOBS` for throughput) |
| `app/31-estate-daemon-deployment.yaml` | estate polling daemon |
| `app/32-estate-telecom-pvc.yaml` | snapshot/registry storage for the daemon |
| `app/40-ingress.yaml` | nginx ingress: TLS termination, HTTP→HTTPS redirect, HSTS, TLS 1.2+ only |
| `app/45-availability.yaml` | PodDisruptionBudgets + NetworkPolicy for the API |
| `neo4j/` | Neo4j StatefulSet + PVC + service (optional — leave `NEO4J_URI` empty to skip) |

## Deploy

The checked-in files are templates and intentionally contain mutable example
references. Render a release only after the registry returns the manifest
Digests for the exact API, worker and Neo4j images:

```bash
python scripts/pin_release_images.py \
  --registry ghcr.io/<org> \
  --api-digest <64-hex-api-manifest-digest> \
  --worker-digest <64-hex-worker-manifest-digest> \
  --neo4j-digest <64-hex-neo4j-manifest-digest> \
  --out /secure/releases/<version>/k8s

kubectl apply -f /secure/releases/<version>/k8s/app/00-namespace.yaml
kubectl apply -f /secure/releases/<version>/k8s/app/10-configmap.yaml
cp app/15-secret.example.yaml /secure/releases/<version>/15-secret.yaml # fill via secret manager
kubectl apply -f /secure/releases/<version>/15-secret.yaml

# Postgres + Redis: run your own (CloudSQL/RDS/ElastiCache or the compose stack),
# then reference them in the secret's DATABASE_URL / REDIS_URL.
kubectl apply -f /secure/releases/<version>/k8s/app/20-api-deployment.yaml -f /secure/releases/<version>/k8s/app/21-api-service.yaml
kubectl apply -f /secure/releases/<version>/k8s/app/30-worker-deployment.yaml
kubectl apply -f /secure/releases/<version>/k8s/app/32-estate-telecom-pvc.yaml
kubectl apply -f /secure/releases/<version>/k8s/app/31-estate-daemon-deployment.yaml
# The TLS secret must exist first, or the ingress serves nothing:
kubectl -n cryptoscan create secret tls cryptoscan-tls --cert=fullchain.pem --key=privkey.pem
kubectl apply -f /secure/releases/<version>/k8s/app/40-ingress.yaml
kubectl apply -f /secure/releases/<version>/k8s/app/45-availability.yaml
```

### Before you apply: the values that are yours, not the template's

| Setting | Where | Why it is not defaulted for you |
|---|---|---|
| `TRUSTED_HOSTS`, `CORS_ORIGINS` | `app/10-configmap.yaml` | Production refuses to boot without an explicit host allow-list and origin list. |
| `TRUSTED_PROXY_COUNT`, `TRUSTED_PROXY_CIDRS` | `app/10-configmap.yaml` | The client IP is resolved once, in `api/security/client_ip.py`. `TRUSTED_PROXY_CIDRS` must be **your** ingress controller's pod CIDR. Wrong and narrow: the socket address wins (fail-safe). Too wide: a direct caller can write its own `X-Forwarded-For`. |
| `ONPREM_DEFAULT_ORG_SLUG`, `ONPREM_DEFAULT_ORG_NAME` | `app/10-configmap.yaml` | One bank, one organisation. See below. |
| `cryptoscan-tls` secret | cluster | TLS terminates at the ingress; the API speaks plain HTTP on the pod network only. |
| image digests | release render | `scripts/pin_release_images.py` is the only approved source of an appliable manifest. |

**Do not add `--proxy-headers` to the container command.** uvicorn would rewrite
the ASGI client address from `X-Forwarded-For` for *any* peer, which defeats the
CIDR check the API performs: the boundary would then be inspecting a string the
client wrote. `scripts/tests/test_deployment_surface.py` fails if any launch path
reintroduces it.

### Single-organisation installs

`ONPREM_SINGLE_ORG: "true"` (the shipped default) provisions the install's
organisation on first use and attaches an account the administrator created at
`ONPREM_AUTO_MEMBERSHIP_ROLE` (default `viewer` — read everything, change
nothing). The grant is written to the tenant provision log with actor
`onprem:auto-membership`, so it is reviewable afterwards. Raising the role to
`admin` or `owner` additionally requires `ONPREM_AUTO_MEMBERSHIP_ADMIN_ACK=true`.
Turn the setting **off** for a multi-tenant or self-serve deployment: combined
with `CRYPTOSCAN_SAAS_SIGNUP` the production gate refuses to boot.

Do not apply `k8s/app/` directly. `scripts/engineering_gate.py` and
`scripts/release_check.py` deliberately fail while mutable template references
are the only available release inputs.

## Notes

- **Migrations:** run once per release before rolling the API. Use the exact
  published OCI digest, never a tag or `latest`:
  `kubectl run cryptoscan-migrate --rm -it --image registry.example/cryptoscan-api@sha256:<API_DIGEST> --env DATABASE_URL=... --
  alembic -c services/database/migrations/alembic.ini upgrade head`. The
  checked-in example manifests remain release templates until the release
  registry supplies the real API/worker/Neo4j digests; run the engineering gate
  and do not approve while it reports mutable references.
- **Secrets:** `SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `GITHUB_WEBHOOK_SECRET`, DB URLs live in the
  Secret. Production validation refuses demo defaults at startup.
- **Backups:** see `docs/admin-guide/backup-restore.md`; run as a CronJob mounting the same image.
- **Scaling:** API is stateless (scale freely). Workers: one replica per ~`MAX_CONCURRENT_JOBS`
  concurrent scans; SQLite is dev-only — use Postgres before scaling workers.

## Required execution/replay configuration

The manifests are templates, not a qualified Redis topology. Mount an approved
CA bundle into the API, set `REDIS_CA_CERTS`, and supply a named non-default ACL
`rediss://` URL through the secret manager. Optional Sentinel needs three distinct
TLS discovery endpoints, a service name and dedicated discovery credentials;
discovered data addresses need matching certificate SANs. Edge ingress TLS does
not provide Redis TLS.

The Sentinel factory covers realtime/current-run state only. Queue/rate-limit/
health clients and service-specific ACLs still require review. Coordinate new
pinning producers/workers and approved legacy-job resubmission. Primary changes
invalidate production replay cursors rather than promising seamless frozen
snapshot continuation. See [upgrade/recovery](../docs/runbooks/execution-and-replay-upgrade.md)
and [qualification boundaries](../docs/bank-environment/45-redis-tls-sentinel-qualification.md).
No manifest, probe or local lab certifies production security/HA.

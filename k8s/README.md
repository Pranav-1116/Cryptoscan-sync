# CryptoScan Kubernetes Manifests

`neo4j/` deploys the optional dependency-graph database.
`app/` deploys the CryptoScan platform itself (API + worker).

## Layout

| File | Purpose |
|---|---|
| `app/00-namespace.yaml` | `cryptoscan` namespace |
| `app/10-configmap.yaml` | non-secret settings (log level, queue key, worker concurrency) |
| `app/15-secret.example.yaml` | template for secrets — copy, fill, `kubectl apply`; never commit the filled copy |
| `app/20-api-deployment.yaml` | API + dashboard (2 replicas, liveness `/health`, readiness `/health`) |
| `app/21-api-service.yaml` | ClusterIP service |
| `app/30-worker-deployment.yaml` | scan worker (scale `replicas` or `MAX_CONCURRENT_JOBS` for throughput) |
| `app/40-ingress.yaml` | nginx ingress example |
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
kubectl apply -f /secure/releases/<version>/k8s/app/40-ingress.yaml
```

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

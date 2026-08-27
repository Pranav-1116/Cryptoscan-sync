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

```bash
kubectl apply -f app/00-namespace.yaml
kubectl apply -f app/10-configmap.yaml
cp app/15-secret.example.yaml app/15-secret.yaml   # edit values, then:
kubectl apply -f app/15-secret.yaml

# Postgres + Redis: run your own (CloudSQL/RDS/ElastiCache or the compose stack),
# then reference them in the secret's DATABASE_URL / REDIS_URL.
kubectl apply -f app/20-api-deployment.yaml -f app/21-api-service.yaml
kubectl apply -f app/30-worker-deployment.yaml
kubectl apply -f app/40-ingress.yaml   # adjust host/TLS for your domain
```

## Notes

- **Migrations:** run once per release before rolling the API:
  `kubectl run cryptoscan-migrate --rm -it --image cryptoscan-api:TAG --env DATABASE_URL=... --
  alembic -c services/database/migrations/alembic.ini upgrade head`
- **Secrets:** `SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `GITHUB_WEBHOOK_SECRET`, DB URLs live in the
  Secret. Production validation refuses demo defaults at startup.
- **Backups:** see `docs/admin-guide/backup-restore.md`; run as a CronJob mounting the same image.
- **Scaling:** API is stateless (scale freely). Workers: one replica per ~`MAX_CONCURRENT_JOBS`
  concurrent scans; SQLite is dev-only — use Postgres before scaling workers.

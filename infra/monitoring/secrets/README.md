# Monitoring secrets

The two files `docker-compose.monitoring.yml` mounts are written here and are
**not committed**:

| File | Read by | Env var it comes from |
|---|---|---|
| `webhook_token` | Alertmanager (`credentials_file` in `alertmanager.yml`) | `ALERTMANAGER_WEBHOOK_TOKEN` |
| `metrics_token` | Prometheus (`bearer_token_file` in `prometheus.yml`) | `METRICS_TOKEN` |

```sh
python3 scripts/render_monitoring_secrets.py            # both files, mode 0400
python3 scripts/render_monitoring_secrets.py --dir /run/secrets/cryptoscan
```

One script writes both from the environment the API reads, because the failure
mode of copying a token by hand is not an error message — it is an Alertmanager
that retries a 401 forever while the pager stays quiet.

`MONITORING_SECRETS_DIR` overrides the directory the overlay mounts. A bank that
already has a secret manager should render these files from it (systemd
`LoadCredential`, Vault agent, Kubernetes `Secret` → volume) rather than keeping
them on the host.

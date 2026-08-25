# Container registry integration

CryptoScan accepts image-push webhooks and scans an already-unpacked
image root, a `docker save` / OCI archive, or a locally available
reference. It does not require a live `docker pull` from the registry.

## Webhooks

| Registry | Endpoint |
|---|---|
| Generic / ECR | `POST /api/v1/webhooks/container` and `/webhooks/ecr` |
| Azure ACR | `POST /api/v1/webhooks/acr` |
| GCR / Artifact Registry | `POST /api/v1/webhooks/gcr` |
| Docker Hub | `POST /api/v1/webhooks/dockerhub` |
| Harbor | `POST /api/v1/webhooks/harbor` |

Payload parsers live in `container_scanner.registry`. Supply one of:

- `path` / `image_root` — unpacked rootfs
- `archive` — `docker save` tarball
- `image` — local reference the puller can resolve

## On-demand scan

```
POST /api/v1/container/scan
{"path": "/var/lib/cryptoscan/images/payments"}
```

or `{"archive": "/tmp/app.tar"}` / `{"image": "payments:1.2"}`.

## Fingerprints

Known OpenSSL / BouncyCastle hashes live in
`services/container_scanner/container_scanner/data/seed/`. Refresh them
with `python scripts/update_fingerprint_db.py`.

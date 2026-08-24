# Container and image-root scanning

CryptoScan inventories cryptographic libraries from an *unpacked* filesystem.
It does not pull images from a registry and does not disassemble binaries.

## What is scanned

- Language manifests: `requirements.txt`, `package.json`, `pom.xml`, `*.csproj`, `go.mod`
- OS package databases: `/var/lib/dpkg/status`, `/lib/apk/db/installed`, `rpm-packages.txt`
- Python `site-packages` `*.dist-info/METADATA`
- Named binaries: `libcrypto.so*`, `*.jar` (BouncyCastle / commons-codec)

CVEs are matched against the local advisory file
`services/container_scanner/container_scanner/data/cve_db.json`.

## Dashboard

**Container → Scan filesystem** and point at a directory such as
`demo/polyglot-app`.

## API

```
POST /api/v1/container/scan   {"path": "/path/to/image-root"}
GET  /api/v1/container/scans
POST /api/v1/webhooks/container
POST /api/v1/webhooks/ecr
```

Registry webhooks accept an already-unpacked `path` / `image_root`. Image
pull is out of scope.

## CLI

```
python scripts/scan_container.py demo/polyglot-app -o container.json
```

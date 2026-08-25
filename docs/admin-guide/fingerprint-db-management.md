# Fingerprint database management

The container scanner identifies crypto libraries two ways:

1. **Package name** — `requirements.txt`, `pom.xml`, `package.json`, OS packages.
2. **SHA-256 of the binary** — `libcrypto.so*`, `libssl.so*`, BouncyCastle JARs.

Catalog: `services/container_scanner/container_scanner/data/fingerprint_db.json`  
Hash seeds: `services/container_scanner/container_scanner/data/seed/*.json`

## Adding a library

```json
{
  "libraries": {
    "openssl": {
      "vendor": "OpenSSL",
      "algorithms": ["AES", "RSA", "ECDSA", "SHA-256", "TLS"],
      "language": "C"
    }
  }
}
```

## Adding a binary hash

```json
{
  "library": "OpenSSL",
  "entries": [
    {"version": "3.0.2", "file": "libssl.so.3", "sha256": "<hex>"}
  ]
}
```

Run `python scripts/update_fingerprint_db.py --check` after editing.
Hashes are loaded at scanner start via `FingerprintRepository.lookup_hash`.
Do not commit production binary blobs; only hex digests.

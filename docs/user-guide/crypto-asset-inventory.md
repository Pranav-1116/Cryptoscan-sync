# Crypto asset inventory

Every scan collapses raw findings into **crypto assets**: one row per
algorithm + purpose + file + line. Open **Assets** on the dashboard or
call `GET /api/v1/assets`.

## What an asset records

| Field | Meaning |
|---|---|
| algorithm / mode / key_size | Normalized crypto (AES-GCM, RSA-2048, …) |
| purpose | Encryption, hashing, TLS, key management, password hashing, … |
| file_path / line_number | Source location or cloud/network resource URI |
| confidence | HIGH when two scanners agree or a binary hash matches |
| system_id | Application that owns the asset |

## Where assets come from

- **Source scanners** (Java, Python, JS/TS, C#, Go, PHP, Ruby, Rust, JAR/PEM)
- **Container fingerprints** (package names + SHA-256 of `libcrypto` / JARs)
- **Cloud live / IaC** (KMS, S3, RDS, ELB, ACM, CloudFront, Secrets, Lambda, API Gateway)
- **Network TLS** (certificates, cipher suites, mesh / DNS targets)

## Filtering

```
GET /api/v1/assets?algorithm=AES
GET /api/v1/assets?purpose=NETWORK_ENCRYPTION
GET /api/v1/systems/{id}
```

Export a CycloneDX 1.5 CBOM for a scan or system from **CBOM** or
`python scripts/export_cbom.py <scan-id>`.

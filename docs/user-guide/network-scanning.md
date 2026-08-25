# Network TLS scanning

CryptoScan can:

- Discover TLS endpoints from `config/network-scan-targets.yaml` and Kubernetes Ingress/Service manifests
- Parse local PEM/CRT material into a certificate inventory
- Validate leaf/issuer linkage, hostname, and expiry
- Extract OCSP and CRL URLs (live fetch stays off unless `CRYPTOSCAN_TLS_LIVE=1`)
- Track each fingerprint's usages (`PEM_FILE`, `TLS_ENDPOINT`, `K8S_SECRET`)
- Schedule targets (`GET /network/due`, `POST /network/run-due`)
- Optionally open a real TLS handshake (`CRYPTOSCAN_TLS_LIVE=1` or the dashboard **Probe host** action)

Live probes stay off by default so CI and tests never phone the internet.

```bash
python scripts/run_network_scan.py demo/polyglot-app
python scripts/run_network_scan.py example.com:443 --live
```

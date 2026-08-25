# Network scan targets

Place `config/network-scan-targets.yaml` in the repo or workspace:

```yaml
targets:
  - endpoint: api.payment.example.com:443
    system_id: payment-api
    scan_frequency: daily
```

The scanner also discovers Ingress/Service hosts from Kubernetes YAML, A records from `*.zone` / hosts files, and TLS metadata from Envoy/Istio access logs. Live probing is off unless `CRYPTOSCAN_TLS_LIVE=1`.

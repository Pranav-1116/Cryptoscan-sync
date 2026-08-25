# Network scanner design

1. Discover targets (YAML, Kubernetes, DNS zone, hosts).
2. Optionally probe TLS (stdlib `ssl`) and parse cipher suites for TLS 1.2 and 1.3.
3. Parse PEM / live peer certs; validate hostname and chain; check OCSP then CRL.
4. Dedup inventory by fingerprint; emit expiry alerts.
5. Parse Envoy/Istio logs for passive confirmation of the same cipher.

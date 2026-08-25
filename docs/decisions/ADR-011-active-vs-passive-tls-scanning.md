# ADR-011 Active vs passive TLS scanning

## Status

Accepted.

## Decision

Active probing is the default: CryptoScan opens a TLS handshake, records version / cipher / certificates, and closes. Passive observation is additive and reads Envoy or Istio access logs when those files are present in the scan tree.

## Consequences

- Public and configured endpoints can be inventoried without a service mesh.
- Mesh logs raise confidence when the same cipher is seen at runtime.
- eBPF remains optional and out of the default delivery.

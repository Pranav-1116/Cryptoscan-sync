# ADR-012 eBPF vs LD_PRELOAD

## Status

Accepted.

## Decision

Do not ship a privileged eBPF agent in the default platform. Network TLS probing plus optional Envoy/Istio log parsing covers the Part 3 runtime visibility goal. An LD_PRELOAD shim is documented as a later alternative if a customer cannot run eBPF and still wants process-level hooks.

## Consequences

- No privileged DaemonSet in the default install.
- Runtime findings still arrive from live TLS probes and mesh logs.

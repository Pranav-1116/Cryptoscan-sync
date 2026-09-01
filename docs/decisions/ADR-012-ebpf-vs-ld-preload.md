# ADR-012 eBPF vs LD_PRELOAD

## Status

Accepted. **Updated 2026-08-31:** the LD_PRELOAD shim now ships as the
runtime crypto-call tracer (`services/runtime/cshim/cryptoscan_trace.c`,
runner in `runtime/agent/preload_trace.py`), per the "later alternative"
documented below. It intercepts libcrypto EVP calls (cipher/mode/key size,
digests, PKEY sign/verify/derive/keygen, TLS version + cipher-list
configuration) in any dynamically linked process — including the openssl
CLI — recording metadata-only JSONL. No kernel agent, no privileges, no
key material.

## Decision

Do not ship a privileged eBPF agent in the default platform. Network TLS probing plus optional Envoy/Istio log parsing covers the Part 3 runtime visibility goal. An LD_PRELOAD shim is documented as a later alternative if a customer cannot run eBPF and still wants process-level hooks — and it has now been built.

## Consequences

- No privileged DaemonSet in the default install.
- Runtime findings still arrive from live TLS probes, mesh logs, and
  (new) the LD_PRELOAD crypto-call tracer:
  `cryptoscan-runtime trace -- <command>`.
- The eBPF path remains out of scope: hooks at kernel level would need
  privileged deployment and are not required for the metadata-only
  inventory this platform promises.

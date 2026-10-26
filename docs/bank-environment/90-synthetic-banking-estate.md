# 90 — Local synthetic banking cryptographic estate

The additive implementation is in [`tools/banking_sandbox`](../../tools/banking_sandbox/). It generates varied, linked banking organizations and all six BOM projections, provides source/configuration/public-PKI/network/runtime/vendor/cloud/hardware/HSM/KMS/PQC fixtures, separates hidden ground truth, runs the unchanged normal static collector under a tested local boundary, and supplies a read-only estate explorer.

- [Quick start and configuration](../../tools/banking_sandbox/docs/README.md)
- [Architecture, evidence semantics and isolation](../../tools/banking_sandbox/docs/architecture.md)
- [35 difficult cases, 15 modes, ecosystems and failure scope](../../tools/banking_sandbox/docs/coverage.md)
- [Operator drift, failure, scoring, benchmarking and VM procedures](../../tools/banking_sandbox/docs/operations.md)
- [Measured readiness and remaining gaps](../readiness-evidence/banking-sandbox-2026-10-26.md)

**Do not equate generated breadth with live capability.** Static collection at 10/50/100/150 banks and a narrow isolated TLS/runtime witness are separate measurements. Network/HSM/cloud/PQC declarations are not live observations; unmeasured database, API and queue capacity remains UNKNOWN. The original full banking-estate specification is **not yet fully accepted**: full live protocol/runtime/HSM coverage, production import/correlation validation and independent review remain outstanding.

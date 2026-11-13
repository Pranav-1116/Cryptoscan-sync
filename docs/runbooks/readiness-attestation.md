# Bank readiness attestations

The strict readiness gate is **not** a certificate or an assessor. It refuses a PASS-shaped external report unless the operator supplies a trusted Ed25519 public key from outside the source repository, the exact site identifier, and a detached signed attestation for that category. The bank/assessor controls the signing key **outside this repository**; CryptoScan never generates, stores, or asks for its private key.

For each external category (`postgresql_dr`, `hsm`, `integrations`, `compliance`, `load_soak`, `browser_journey`, `operational_policy`, `readiness_closure`, `external_attestations`, and, when supplied, `production_orchestrator`), retain the original report and a `<category>.attestation.json` in the operator-controlled attestation directory. The attestation body has these exact fields:

```json
{
  "schema": "cryptoscan.readiness-attestation/1",
  "algorithm": "Ed25519",
  "category": "hsm",
  "artifact_sha256": "<SHA-256 of the exact report bytes>",
  "repository_commit": "<full 40-character Git commit>",
  "site_id": "<bank-approved installation identifier>",
  "issued_at": "<timezone-aware ISO-8601 timestamp>",
  "key_id": "<approved public-key identifier>",
  "issuer": "<approved assessor or bank evidence owner>",
  "approval_ref": "<bank-controlled review reference>",
  "signature": "<base64 Ed25519 signature>"
}
```

The separate `binary_async_durability` category is an in-process engineering gate, not a signable waiver: it remains FAIL while the Binary API uses its process-local queue. `browser_journey` requires a signed `cryptoscan.browser-journey/1` report from a real browser against the bank-owned staging site, not Vitest output. It must name the site, repository commit and browser version, with PASS entries and retained trace SHA-256 digests for `login`, `authorized_scan`, `retained_evidence`, `six_boms`, `digital_twin`, `simulation_unchanged` and `remediation_rescan`. The gate checks shape/signature, not whether the traces genuinely show those events; the bank reviewer must inspect the retained traces.

The signature covers the UTF-8 JSON object **without `signature`**, serialized with sorted keys, compact separators `(',', ':')`, and `ensure_ascii=False`. The verifier checks the exact report-byte digest, category, site, revision, schema, timestamp shape, and signature against the operator's trust anchor. No key material belongs in the report or attestation. Keep the report, attestation, public-key approval record, signer access log and reviewer decision in the bank's retention system.

Run `scripts/bank_readiness.py --strict --site-id <site> --trusted-public-key <bank-public.pem> --attestation-dir <receipts-dir> --postgresql-dr <report> --browser-journey <report> ...` after a clean committed build and the bank's actual exercises. Missing receipts, an unapproved operational policy, dirty source, or a failed category remain FAIL/SKIP. A valid signature authenticates **who signed these exact bytes under the supplied key**; it does not prove that the exercise occurred, that its claims are true, or that the bank approved deployment. Independent assessment and change approval are separate human gates.

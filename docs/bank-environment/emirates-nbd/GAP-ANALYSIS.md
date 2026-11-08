# Emirates NBD engagement — gap analysis (tool vs. baseline needs)

> Scope: what the Emirates NBD public-source baseline
> (`public-source-baseline-2026-11-07.md` / `baseline-dataset-2026-11-07.json`)
> needs from the platform, what exists today, and what is missing.
> Rule applied throughout: a capability is only listed as AVAILABLE
> where a tested, working path exists. Register-only items stay
> register-only — they are never presented as built.

## 1. What this slice built (tested)

| Baseline need | Capability | Where | Proven by |
|---|---|---|---|
| §4–8 sourced inventory of disclosed tech/vendors | `DisclosureRecord` + loader (refs, confidence key, as-of, currency rule) | `services/vendor_intel/vendor_intel/public_source.py` | `services/vendor_intel/tests/test_public_source.py` (26 tests) |
| §8 consolidated vendor register | `PublicSourceBaseline.vendor_register()` (derived, "first seen ≠ contract date") | same | `TestVendorRegister` |
| §9 crypto-siting map, "clearly labelled as inference" | `SitingHypothesis` — `evidence_class="inferred"` always, questions preserved | same | `TestInferenceNeverClaims` (incl. `claims() == []`) |
| §10 unverified claims (QKD pilot) | `UnverifiedClaim` — recorded, never asserted | same | `TestUnverifiedAndGaps` |
| §10 gaps ("Do not assume any") | `GapRecord` — a gap is NEVER an absence claim | same | same |
| §11 data request list (11 categories) | `DataRequest` + `advance_request()` — status advances ONLY against imported evidence (actor/date/artifact); no external act is ever marked done from inside the repo | same | `TestDataRequestList` |
| Currency rule ("was deployed", not "is deployed") | `current_state_confirmed` structurally always False for public-source rows | same | `TestCurrencyDiscipline` |
| Discovery ("I want to discover that also") — first stage | `match_observation()` — content-token candidate matching against the disclosed register; a candidate is never confirmation; no-match is never "product absent" | same | `TestDiscoveryMatching` |

## 2. Existing platform capabilities this engagement reuses

| Baseline need | Existing capability | Status |
|---|---|---|
| §11 certificate inventory (item 3) | OS & Kernel Intelligence certificate metadata (`certificates.py`, `os_certificates`, `/assets/{id}/certificates`) — REAL collection for Linux/macOS/Windows outputs | Delivered (tested) |
| §11 TLS baselines (item 4, config axis) | OS-CRYPTO-006 + SCHANNEL registry parsing (enabled-by-config axis; supported/observed-negotiated stay distinct) | Delivered for OS config; per-tier service TLS is open (§3) |
| §11 software supply chain / SBOM (item 9) | OS BOM projections (`sbom/cbom/hbom/techbom`), Binary Intelligence SBOM/CBOM, vendor `vbom` | Delivered at host/binary/vendor level |
| §11 PQC readiness (item 10) | `quantum` service plan/risk modules; PQC presence ≠ PQC use discipline | Partial — roadmap modelling only |
| §11 payment/card crypto (item 6) | `payment_crypto` service | Partial — engine exists; bank-specific evidence not collected |
| §2 CBOM construction | `cbom` service (CycloneDX 1.6 crypto-asset model) + OS-engine `cryptoscan.os-bom/1` | Delivered locally; external CycloneDX export wiring is register-only (standing) |
| Estate discovery | `network_scanner` + digital-twin (`os_relationships`) | Delivered; bank-scope discovery requires authorisation (§4) |

## 3. Open gaps (honest, in baseline order)

| # | Gap | Reality | Where it goes next |
|---|---|---|---|
| G1 | HSM inventory (§11 item 1) | **Register-only forever** (standing constraint). The platform records and tracks HSM data once the bank supplies it; it never scans or benchmarks HSMs. | `DataRequest(req-hsm-inventory)` + `keyassure`/`vaultlease` records once data arrives |
| G2 | PKI hierarchy detail (item 2) | Not collected today. Certificate METADATA exists; CA hierarchy/signature-algorithm mapping needs supplied PKI data or authorised collection. | request `req-pki`; engine extension when evidence arrives |
| G3 | Per-tier TLS/SSH baselines (item 4) | OS-level config axis only; service-level TLS (load balancers, gateways, DBs) needs authorised in-scope collection. | request `req-tls-ssh-baselines` + scoped network collection |
| G4 | Network crypto parameters (item 5) | IPsec/IKE parameters need authorised collection; job-advert evidence stays `low_medium`. | request `req-network-crypto` |
| G5 | Core/DB encryption (item 7) | OS-level disk metadata exists (LUKS/BitLocker/FileVault); TDE/tokenisation/backup crypto needs supplied data. | request `req-core-db-encryption` |
| G6 | Cloud KMS/BYOK (item 8) | KMS/HSM benchmarks are register-only (standing). Inventory recording exists (`inventory/cloud_kms.py`). | request `req-cloud-kms` + inventory recording |
| G7 | Vendor PQC roadmaps (item 10) | Vendor statements must be collected per vendor; the questionnaire pipeline (`vendor_intel/questionnaire.py`) exists to receive them. | `req-vendor-pqc-roadmaps` → questionnaire intake |
| G8 | Data-retention classes (item 11) | Business data classification — only the bank can supply it. | request `req-data-retention` |
| G9 | Discovery stage 2 — estate fingerprinting | Candidate matching (stage 1) ships now; confirmed product identification needs authorised scanning evidence correlated with the register. | `match_observation` + `network_scanner` evidence pipeline |
| G10 | QKD pilot verification | Stays an **unverified claim** until the bank or Toshiba confirms — never asserted, never drawn as truth. | `UnverifiedClaim(qkd-pilot-toshiba)` |

## 4. Engagement boundary (standing)

- All discovery tooling runs ONLY inside an agreed scope; this repo
  performs no scanning, probing or non-public collection.
- HSM/KMS/PQC benchmarks, real exporter wiring and bank pilot
  acceptance are **register-only forever** — the platform records,
  tracks and projects; it never fabricates those results.
- External acts (sending requests, receiving data, bank confirmations)
  are recorded only as imported evidence — never marked done from
  inside the repo.

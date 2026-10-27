# Hardware crypto catalog (HSMs, key stores, mainframe)

`GET /api/v1/hardware/catalog` is the curated registry of cryptographic
hardware the platform recognizes: networked HSMs, cloud key-management
services, key stores, and mainframe crypto (IBM Z, ARM CCA). Every entry
carries: `category`, `manufacturer`, recognition info, and a
**`quantum_resistant`** flag with a `risk_reason`/`notes` field that cites
the evidence. The catalog response includes `quantum_resistant_count` so
dashboards can show "X of Y device types ship PQC support today"
(currently **10 of 60**). Dashboard: **Hardware** / **Catalog** pages.

## Where the flags come from (provenance policy)

The registry is sourced in `shared/shared_models/hardware_registry.py` and
follows one rule, pinned by tests
(`services/universal_vendor/tests/test_hardware_registry_vendors.py`):

> A device is `quantum_resistant: true` **only if PQC support is shipping
> today**, at a named firmware level. Announcements and roadmaps are not
> evidence. Every note carries the firmware citation.

As of 2026-09 (verified against vendor announcements before each flag was
set):

| Device | Flag | Shipping evidence |
|---|---|---|
| Thales Luna (fw 7.9+) | ✅ | ML-KEM/ML-DSA in core firmware (FM no longer required) |
| Entrust nShield (fw 13.8.0+) | ✅ | CAVP-validated ML-KEM/ML-DSA/SLH-DSA |
| Utimaco SecurityServer (fw 5.5) | ✅ | validated module covering ML-DSA-65 |
| AWS CloudHSM / KMS | ✅ | managed-firmware PQC; KMS internal HSM covers ML-DSA-65 |
| IBM Z / LinuxONE (CEX8+) | ✅ | PQC via licensed internal features |
| Google Cloud HSM | ✅ | managed-firmware PQC |
| ARM CCA (device attestation) | ✅ | hardware rooted trust incl. PQC-ready attestation |
| Azure Dedicated HSM | ⚠️ | user-managed Luna 7 firmware — **customer** must upgrade to 7.9+ |
| Thales payShield | ❌ | roadmap announced, **not yet shipping** |

The registry module docstring carries the full provenance. When vendors
ship, the flag changes **with a firmware citation and a pinned test** —
never because a press release said so.

## Live hardware telemetry (separate surface)

The catalog is static truth about device *models*. Live estates run the
hardware agent engine (ADR-014): `POST /hardware/heartbeats`,
`POST /hardware/events[/batch]`, `GET /hardware/state`, `GET
/hardware/timeline`, `GET /hardware/risk`, `GET /hardware/incidents`,
`GET /hardware/agents` (health), `GET /hardware/hbom/versions`, and
`POST /hardware/reaction-plan` for incident response. See
[architecture/service-map.md](../architecture/service-map.md) for how the
two surfaces relate.

## Why this matters for a PQC program

The migration plan is only as honest as the "can this box do ML-KEM *this
quarter*?" answer. The catalog exists to make that answer auditable: every
flag is either shipping-cited or conservatively `false`, and
`quantum_resistant_count` on the catalog API is the one-number summary a
steering committee can track quarter over quarter.

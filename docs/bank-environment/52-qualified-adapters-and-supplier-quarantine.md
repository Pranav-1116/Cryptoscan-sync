# 3.7 — Fewer exercised profiles, supplier quarantine and explicit trust

## Registry presence is not support

Connector SDK discovery now explicitly reports `REGISTERED_NOT_QUALIFIED`,
including implementations overriding `describe()`. The registry still discovers
code; it does not self-issue production/vendor support. Controlled execution does
not acquire permission to call those classes.

A new manifest names **one vendor/product/version/profile/format**, required
permissions, collected fields, explicit pagination/partial contract, request rate,
retry count/backoff, exclusions and evidence reference. There is no fuzzy name
or broad “all versions” support claim.

The implemented parser is deliberately narrow: **`vendor-export/v1-json`**, an
internal bounded, typed offline interchange—not a claim that a proprietary
vendor's original format/API is supported. Facts separately model versioned
packages, endpoints/declared services, purpose-aware crypto, declared deployment/
artifact links, product/firmware/hardware-backed/mode data, and supplier/product/
version declarations. Unknown firmware/mode/use remain null. No live permissions,
API pagination, vendor 429s or retry/load behavior have been exercised merely by
validating an offline document; the manifest says so explicitly.

## Intake → origin/build checks → different human review

1. CISO/admin registers an approved **Ed25519 public key** with expiry and evidence
   reference. Private keys are neither requested nor stored. Rotation creates a
   new signer ID; an existing historical key cannot be replaced. Revocation and
   expiry are checked at consumption time.
2. A separate uploader submits an existing exact-estate artifact ID and a signed
   supplier manifest plus base64 payload. Signature input is the server's
   deterministic UTF-8 JSON representation of the typed manifest (sorted keys,
   compact separators, explicit UTC timestamps). Use the exact typed manifest's
   canonical bytes; timestamp reformatting changes the signature.
3. The manifest binds customer ID (`tenant_id`, or literal `platform` only for the
   platform estate), explicit signed `estate_scope` (`tenant:<tenant_id>` or
   `platform` using the existing scope-key contract), exact build digest, payload SHA-256, vendor/product/version/
   profile/format, collection time and expiry. The server hashes the bytes and
   verifies the envelope against the trusted selected-estate signer.
4. **Every intake starts QUARANTINED.** Payload bytes are not parsed at intake,
   even for a trusted signer. Wrong customer/build, stale/future/invalid time,
   digest mismatch and untrusted/invalid signer are retained as problems. Invalid
   request contracts/base64/size are refused at admission, not executed.
5. A different entitled human approves or rejects it. Approval rechecks current
   key trust, customer, build, digest and freshness, then validates only bounded
   JSON. Malformed payloads remain quarantined with MALFORMED. No XML, archive,
   shell, URL fetch or vendor code is invoked.
6. `origin_verified` records signature/digest provenance, not independent truth.
   An approved offline payload is **not** a deployed release, firmware-mode proof,
   certification or independent supplier due diligence.

The bound artifact may itself be a declared digest: that identity source remains
visible in existing artifact history. A match against a declared digest does not
magically measure the running release. Raw evidence bytes require privileged
CISO/admin human access and regional encrypted/quota-controlled SQL/storage.
Supplier raw bytes additionally require current customer/build/trust and bounded
format approval; wrong-customer, stale, revoked, malformed and other quarantined
supplier bytes are not downloadable through this API even by an estate CISO.

## Qualification actually executes the bounded adapter

An entitled reviewer submits seven **distinct retained fixture cases** against
the exact manifest:

- COMPLETE, with the independently reviewed golden normalized-output SHA-256;
- PARTIAL, with an explicit missing-page/item denominator and golden SHA-256;
- WRONG_CUSTOMER;
- WRONG_BUILD;
- STALE;
- UNTRUSTED_SIGNER;
- MALFORMED.

`/assurance/adapters/{id}/qualifications` runs the identity/trust and bounded-parser
checks; it does not accept a caller's PASS label. Valid positive fixtures need
separate supplier approval and may not emit fields outside the manifest. The
receipt retains actual/expected outcomes, input/evidence/output hashes, collected
fields, execution date, 30-day expiry, parser/schema implementation fingerprint
and explicit nonqualified capabilities. Changed parser/schema/validation-runtime
fingerprints require requalification; this is narrower than a signed full-image
or dependency/supply-chain attestation.
A later failing qualification supersedes a previous passing one. Manifest
changes, positive-fixture trust revocation/rejection/expiry and qualification
expiry invalidate current exercised status.

A current passing result means **OFFLINE_PROFILE_EXERCISED**, never live-vendor
SUPPORTED. The qualified observations endpoint rechecks current manifest/trust/
freshness and emits typed supplier declarations with source hashes and no
automatic identity joins. Complete pages can still contain no observed facts;
recording, observation, collection completeness and posture remain independent.
Duplicate/out-of-range pages, a complete page set with inconsistent item totals,
unknown fields, duplicate JSON keys, nonfinite constants, excessive nesting,
more than 20 pages/2,000 facts or oversized bytes are refused.

## Remaining real-vendor acceptance

No actual named-vendor customer profile, credentials, proprietary export or bank
runtime environment was supplied here. The synthetic fixture supplier in tests is
explicitly not a real supported product. To qualify a live vendor profile, retain
actual approved version/format/permissions, authentication and read-only tests,
pagination/partial behavior, retry/rate limits, representative load and exclusions,
plus customer owner review and independent supplier/product/version checks.
Do not label the broader connector registry SUPPORTED until those exact profile
runs exist. This increment is a deliberately smaller offline lane with real
exercised tests and honest external gaps, not a checklist claiming hundreds of
vendor integrations.

See the [upgrade runbook](../runbooks/evidence-assurance-upgrade.md).

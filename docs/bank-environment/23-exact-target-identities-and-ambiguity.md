# 23 — Exact target identities and ambiguity

**Implemented step 7, 18 October 2026.** Certificate, package and vendor selection
now prefers canonical identities over names. Ambiguity is a result to review,
not permission to choose the first inventory row. The policy is recorded as
`cryptoscan.target-resolution/1` on new unified-cascade runs.

[Guide index](README.md) · [Ten-step status](../dev/dependency-intelligence-roadmap.md)

## 1. Why selection and downstream joins both matter

A bank can renew `CN=payments.bank` while retaining its old certificate during
a rollout. Two certificates can share that subject but have different public
keys, expiry dates and SHA-256 fingerprints. Selecting the old fingerprint and
then joining endpoints by subject would still pull the new certificate's owners
into the old certificate's direct exposure. Exact selection alone did not fix
that problem.

The implementation now preserves the scanner's **leaf certificate fingerprint**
through `probe_to_endpoint`, network inventory and the twin snapshot. Certificate
cascade binds endpoints by that fingerprint—not subject containment, equal
subject, serial number, host name or issuer-chain membership. Declared
`CertificateUsage` system locations are also joined by fingerprint. Case and
colon formatting are normalized consistently in the joins and seed explanations.

An endpoint's registered system owner remains a declaration. Finding a matching
leaf fingerprint does not independently verify that owner, current runtime use,
or failure following a replacement. Evidence pointers remain unverified here.

## 2. Selection rules

| Target | Preferred identity | Name behavior / boundary |
|---|---|---|
| Certificate | Full SHA-256 hex fingerprint; case/32-byte colon formatting normalized | Exact whole-subject comparison is a weaker selection aid; only a unique usable identity can resolve. Multiple fingerprints are ambiguous. No X.509 DN equivalence or subject-to-owner inference |
| Package | Exact version-bearing PURL in explicitly bound SBOM components | Version, ecosystem, case, qualifiers and subpath remain significant. No version-range, tag or package-equivalence guessing; searching a name does not imply deployment |
| Vendor | Exact opaque registry ID, case-sensitive | Then exact whole-name comparison with trim/casefold. Multiple IDs sharing the normalized name are ambiguous; product/version identity is not inferred from a company name |
| Artifact (adjacent safeguard) | Exact registered ID when `kind=artifact`, or full `sha256:` release digest | Multiple artifact IDs for a digest require selection. Automatic plain IDs retain system interpretation; they do not steal an existing system ID |

For certificate input, 64 hexadecimal characters or 32 colon-separated hex bytes
are accepted. `sha256:<hex>` is accepted with **explicit `kind=certificate`**.
Without that kind, `sha256:` retains its release-artifact meaning. SSH
`SHA256:<base64>` fingerprints, short hashes and malformed hex are not X.509
certificate identities.

In automatic detection, supported exact registry IDs take precedence over names;
for example, a system ID wins over another vendor's display name. Colliding
supported IDs across kinds are ambiguous; specify the intended kind. A recognized
fingerprint/PURL/digest form cannot fall through to an unrelated display name.
A partial certificate/vendor name cannot silently become an automatic device
manufacturer match; use explicit device scope for that legacy interpretation.

An exact unique subject/name is labeled `exact_name`, not `exact_identity`.
After selection, the cascade always carries its canonical fingerprint/vendor ID.
A renewal that changes the canonical identity is not an ordinary impact change
for history/watch comparison purposes.

**Scope qualification:** endpoint, device, library, process and algorithm
fallback detectors retain their older semantics where used, labeled
`legacy_detector`. Explicit device manufacturer and algorithm-family queries
are not newly certified exact. A bare package-like name may describe independent
CBOM library evidence under that legacy interpretation; use `kind=package` to
request package/SBOM semantics, or an exact PURL. No universal cross-kind
identity service, vendor product/version registry or runtime attestation is added.

## 3. Broad search is opt-in discovery, not a cascade

`POST /api/v1/technology-bom/cascade` accepts `allow_name_search`, default `false`.

1. Exact identity tiers run first.
2. Exact whole names can resolve only to a unique usable canonical identity.
3. With no exact match, opt-in broad name search returns **choices only**.
4. Even one substring result does not execute impact analysis. Submit a second
   request using its `kind` and `canonical_target`.

The flag permits broad fallback; it does not disable exact matching or turn
all requests into search-only requests. Package searches inspect recorded PURLs,
not an external package index. Automatic opt-in search can return package,
certificate and vendor choices together. Explicit kind constrains the search.

Example discovery request (substitute an authorized inventory term):

```json
{
  "target": "Bank Crypto",
  "kind": "vendor",
  "allow_name_search": true,
  "max_depth": 6
}
```

If this is only a substring of registered names, the answer has
`target_resolution.status=SEARCH_RESULTS`, `selected=null`, and
`analysis_performed=false`. If it is already a unique exact name, exact-name
resolution can execute instead. A deliberate canonical selection looks like:

```json
{
  "target": "vendor-payments-hsm",
  "kind": "vendor",
  "allow_name_search": false,
  "max_depth": 6
}
```

The console supplies an unchecked broad-search checkbox, candidate identities,
and explicit “Analyze exact identity” buttons. A selection sends a new exact,
kind-scoped request with broad search disabled. Conflicting canonical records
cannot be selected through a button; repair the registry first.

## 4. Ambiguity, bounds and incomplete inventory

`target_resolution` includes schema, original input, requested kind, search
choice, matching method, canonical selected summary, candidates, total loaded
candidate count, 50-candidate display limit and a truncation flag.

- `RESOLVED`: analysis may proceed; a name-based decision remains weaker than
  exact identity input and is identified as such.
- `AMBIGUOUS`: several canonical candidates, conflicting records for one key,
  or an unusable canonical identity. No first-row selection.
- `INCOMPLETE`: a known-truncated relevant name registry cannot establish a
  unique name. A loaded exact canonical identity can still be selected.
- `SEARCH_RESULTS`: broad candidate discovery only.
- `NOT_FOUND`: no permitted match in the loaded authorized snapshot; not a
  whole-bank absence/safety finding. Invalid package selectors do not become
  package identities. A blank selector is invalid/rejected by request handling.

Identical duplicate projections are deduplicated. Certificate fingerprint
formatting differences alone are not conflicts; differing records for the same
canonical certificate/vendor key are retained as a conflict instead of choosing
an arbitrary version. Candidate order and conflict presentation do not depend
on input row order. Candidate summaries whitelist identity/display fields, not
contracts or full source rows. Counts are over **loaded canonical candidates**,
not all registry records or external/global matches; a missing canonical identity
can produce an unselectable repair placeholder.

Live certificate/vendor snapshot reads use deterministic order and cap-plus-one
detection. Known truncated name inventories cannot certify uniqueness. Legacy
snapshots without coverage metadata remain **unknown coverage**, not backfilled
with a completeness claim. Software source-cap metadata is carried when present.
No display cap changes candidate ambiguity or system/process counts.

Unresolved answers retain empty legacy impact fields for compatibility but set
`analysis_performed=false`. These are **not analyzed zeroes**. The console hides
impact/process/lifecycle panels for these answers and labels their history entries
“not analyzed”. Events carry the resolution and analysis flag, not an “all clear”.

## 5. Certificate binding gaps are not repaired with names

`layers.network.certificate_join` records the selected fingerprint and exact-leaf
join method. It also counts same-subject endpoints with:

- **No usable fingerprint:** retained as an explicit coverage gap, not included
  as owners of the selected certificate. At most 200 endpoint identifiers are
  listed; the count is not reduced by that listing bound.
- **A different valid fingerprint:** excluded as different certificate evidence,
  not merged because a subject is shared.

The console shows both counts separately. Historical subject-only endpoint
snapshots are not silently enriched with today's fingerprint. Re-evaluation
under the current resolver can therefore have fewer direct owners, with a
binding gap—not a claim that remediation occurred. A certificate without any
exact loaded endpoint/usage binding has unknown consumers.

## 6. Frozen history, replay and watches

New persisted runs freeze the input/search decision, resolution schema, selected
canonical identity, candidates and `analysis_performed`. Fetching a past answer
returns its original stored result. Replay evaluates a captured inventory under
the current named resolution policy and captured/explicit clock; it does not
rewrite that snapshot or an earlier result.

Diffs require both stored runs to have the current resolution schema, completed
analysis and the **same selected kind + canonical identity**. The existing
same-input history lookup and relationship/process policy gates still apply.
Unknown/legacy selection, unresolved search or a changed canonical identity
withholds impact deltas: empty added/removed lists, null before/after counts and
an explicit `target_comparison.comparable=false` reason. Classification/process
comparisons are unavailable too. Old decisions are never reconstructed from
current inventory to make a comparison pass.

Watches use exact/default matching—never automatic broad search. Each attempt is
still saved for audit. Missing/ambiguous targets or a changed/unknown canonical
baseline require attention, do not emit false removal alerts, and **retain the
last resolved comparable baseline**. Once the same canonical target resolves
again, comparison can resume against that baseline. A legacy baseline or an
intentional certificate replacement needs operator review and a new exact-identity
watch; this change does not add an automatic rebaseline action or notification
scheduler. Exact fingerprint/vendor-ID/PURL watches are preferable to names.

## 7. Reproduce the shared-subject boundary locally

Run from the checkout root with the backend dependencies installed:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python - <<'PY'
from datetime import datetime, timezone
from cbom.unified_cascade import unified_cascade
now = datetime(2026, 10, 18, tzinfo=timezone.utc)
a, b = 'ab' * 32, 'cd' * 32
estate = {
    'systems': [{'id': 'payments'}, {'id': 'other'}],
    'certificates': [
        {'fingerprint_sha256': a, 'subject': 'CN=payments.bank'},
        {'fingerprint_sha256': b, 'subject': 'CN=payments.bank'}],
    'network_endpoints': [
        {'host': 'old.bank', 'port': 443, 'system_id': 'payments',
         'certificate_subject': 'CN=payments.bank', 'certificate_fingerprint_sha256': a},
        {'host': 'new.bank', 'port': 443, 'system_id': 'other',
         'certificate_subject': 'CN=payments.bank', 'certificate_fingerprint_sha256': b},
        {'host': 'legacy.bank', 'port': 443, 'system_id': 'other',
         'certificate_subject': 'CN=payments.bank'}]}
ambiguous = unified_cascade(estate, target='CN=payments.bank', kind='certificate', now=now)
assert ambiguous['target_resolution']['status'] == 'AMBIGUOUS'
assert ambiguous['analysis_performed'] is False
selected = unified_cascade(estate, target=a, kind='certificate', now=now)
assert selected['layers']['network']['endpoints'] == ['old.bank:443']
assert selected['impact']['system_classification']['direct_exposure']['systems'] == ['payments']
assert selected['layers']['network']['certificate_join']['subject_only_endpoint_count'] == 1
assert selected['layers']['network']['certificate_join']['different_fingerprint_same_subject_count'] == 1
print('Exact certificate boundary: PASS; no runtime failure claim')
PY
```

## 8. Validation and remaining qualification

Regression coverage includes fingerprint formatting/invalid SSH forms, equal
subjects and name/ID collisions, vendor-ID case, deterministic conflicts and
candidate bounds, version/qualifier/subpath package negatives, explicit broad
selection, actual probe→snapshot propagation, tenant-scoped search candidates,
legacy replay gaps, immutable stored decisions, unavailable diffs and retained
watch baselines. Console tests cover candidate selection, disabled conflict
choices, unresolved zero-count suppression, history and binding-gap warnings.

Final local release-check results are recorded in the ten-step status document.
No new migration is required by step 7; earlier migration requirements remain.
These SQLite/unit and frontend checks are not production PostgreSQL/Neo4j,
whole-bank authorization, complete-source inventory or runtime certification.
Steps **8–10 remain pending**: operational dependency modes, comprehensive
coverage UX, and bank-specific negative/backend qualification. NBOM, CBOM, SBOM,
TechBOM, HBOM and VBOM retain their distinct evidence and coverage meanings.

# 3.6 — Purpose, context and applicability without rewriting observations

`POST /api/v1/assurance/findings/{evidence_id}/assessments` creates a reviewed,
versioned assessment. The immutable original EvidenceRecord's algorithm, purpose,
key size/mode, location and content/chain hashes are copied into the assessment;
its finding payload, chain, original purpose and scanner policy are **not edited**.

Each assessment records purpose, security/nonsecurity use, production/test/unknown,
packaged/invoked/unknown, rationale/evidence reference, contextual importance,
uncertainty, recommendation and recommendation evidence. Context is explicitly a
customer assertion, not independent invocation verification. Posture remains
`null` pending separate applicable policy evaluation.

## Practical changes in recommendation

| Same observed fact | Context | Recommendation changes, observation does not |
|---|---|---|
| MD5 at a source location | Nonsecurity cache checksum, test, packaged | Do not demand a cryptographic migration solely from that checksum; prevent security reuse and investigate separately |
| Same MD5 | Production security integrity use | Review security hash requirements and migration; verify deployed/invoked applicability |
| RSA in certificate evidence | Certificate signature | Review certificate/issuer chain and lifecycle; do not call it negotiated key exchange |
| RSA/key-agreement reference | Key exchange | Verify actual negotiation and peer compatibility; availability/reference is not negotiation |
| AES | Symmetric use | Review exact key size, mode, nonce and lifecycle rather than treating the name as sufficient |

A checksum context conflicting with an originally recorded signing/encryption/
authentication/TLS purpose produces **context conflict requiring review**, not an
automatic downgrade. Hardcoded-key evidence remains an independent investigation
regardless of test/checksum context. Test scope changes priority, not the fact or
potential production reuse. Unknown scope/use stays an explicit uncertainty.

## Version vulnerability applicability

A vulnerability/advisory name is not applicability. The current implemented range
lane requires an exact versioned PyPI package in the specified active, unexpired
SBOM binding and a valid declared PEP 440 affected-version range. The result is
`VERSION_IN_DECLARED_RANGE` or `VERSION_OUTSIDE_DECLARED_RANGE`, not “exploitable”
or “safe.” Advisory authenticity, vulnerable configuration, reachability and
runtime invocation remain unresolved. Missing identities/ranges remain UNKNOWN;
other ecosystems/range semantics are deliberately not guessed.

## Certification labels

A label such as FIPS does not establish module/version/mode. Missing exact fields
produce `INSUFFICIENT_EXACT_MODULE_VERSION_MODE`; differing fields produce a
mismatch. Even a declared exact match is
`DECLARED_EXACT_MATCH_NOT_INDEPENDENTLY_VALIDATED`: the API does not independently
verify a certificate, validated hardware boundary, enabled approved mode or the
running module from customer-supplied strings.

Use `expected_revision=0` for the first assessment and the actual current revision
for the next. History retains both recommendations and the unchanged original
observation. The older global algorithm-only policy/report projections are not
silently overwritten or declared fully context-aware by this new endpoint.

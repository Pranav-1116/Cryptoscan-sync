# Developer and extension guide

## 1. Extension principles

CryptoScan is a platform of services, scanners, policy definitions, reporting
adapters, and connectors. An extension must preserve the core invariants:

- collection is authorized and bounded;
- secret values and private keys are not copied into evidence;
- every observation has provenance;
- unknown and unsupported states remain explicit;
- policy decisions are deterministic and versioned;
- tenant/customer scope is carried through background work;
- external actions are idempotent and approval-aware; and
- tests cover positive, negative, malformed, and unavailable inputs.

Read the [plugin SDK](../../plugin-sdk.md), architecture decisions, service
tests, and existing implementations before adding a new integration.

## 2. Adding a collector

Define:

1. source type and authorization model;
2. required permissions and credential lifetime;
3. network behavior and rate limits;
4. input formats and size caps;
5. parser/scanner identity and version;
6. observation schema;
7. redaction and sensitive-data rules;
8. canonical normalization mapping;
9. unsupported and failure taxonomy;
10. evidence and asset relationships;
11. policy applicability;
12. job progress and cancellation behavior;
13. fixture corpus and test cases; and
14. documentation and operational runbook.

A collector should be deterministic for the same input and configuration where
possible. If an external API returns changing data, retain the retrieval time,
provider/account scope, and relevant response metadata.

## 3. Adding a policy rule

A rule must include:

- stable ID and version;
- condition vocabulary supported by the engine;
- required fields and missing-field behavior;
- applicable policy scope;
- severity and result mapping;
- remediation text;
- test fixtures;
- owner and review date; and
- release notes for behavior changes.

A policy rule should never silently broaden its scope. If the customer needs a
custom rule, keep it in a named pack or controlled override and record who
approved the deviation.

## 4. Adding a connector

A connector should separate pure payload mapping from network delivery:

```text
internal event
  -> scope/permission check
  -> preview payload
  -> idempotency key
  -> signed/authenticated request
  -> receiver response
  -> retry/dead-letter record
```

Test the mapper without network access. Test the sender with a controlled fake
or sandbox. Never expose credentials in preview output, status endpoints, or
logs. Document provider API version, timeout, retry, rate, and deletion
behavior.

## 5. API and schema changes

For a public route or response change:

- update the Pydantic/schema contract;
- add authentication, permission, scope, and negative tests;
- preserve pagination and error shape where compatibility requires;
- document idempotency and job lifecycle;
- regenerate the API reference if generated;
- update client examples and changelog; and
- record an ADR for material architectural behavior.

A route that exists in code but lacks scope, permission, or failure tests is not
ready for external documentation.

## 6. Evidence-safe coding

When processing a finding, source file, provider response, or credential:

- use allowlists for fields that may leave the source boundary;
- redact before hashing or logging if the hash of raw content is not permitted;
- avoid exception messages that include payloads or secrets;
- do not serialize request headers blindly;
- attach source and revision metadata;
- preserve stable identity and provenance; and
- test that planted fake secrets do not reach packs or exports.

## 7. Testing matrix

Every extension should have:

| Test class | Required question |
|---|---|
| Unit | Does the parser/mapping produce the expected result? |
| Negative | Does malformed, unauthorized, or unsupported input fail safely? |
| Privacy | Are secrets and Personal Data redacted? |
| Scope | Can a caller or worker cross customer/system boundaries? |
| Idempotency | Does retry avoid duplicate records or external actions? |
| Migration | Does the schema upgrade from the supported prior state? |
| Integration | Does the real dependency behave under configured credentials? |
| Performance | Does size/rate/timeout behavior remain bounded? |
| Recovery | Can interrupted work resume or be safely replayed? |
| Documentation | Do examples and reference schemas match behavior? |

## 8. Contribution checklist

Before merge:

- code owners reviewed the boundary;
- tests pass offline and integration tests are clearly marked;
- secrets and fixtures are synthetic;
- migration and rollback implications are documented;
- API and user/admin docs are updated;
- product maturity label is correct;
- security/privacy review is complete where needed; and
- release notes describe breaking changes and operational action.

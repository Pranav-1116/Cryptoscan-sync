# Supported, configured, negotiated: three states, three evidences

`cryptoscan.cbom-tls-state-guide/1` · generated 2026-11-02T19:05:32.561232+00:00 · **5 pass · 0 partial · 0 fail** · 27 probes

Review item 7: `TLS 1.2 supported` is not `TLS 1.2 in use`, and `TLS 1.3 negotiated` does not prove it is the only supported protocol. The NBOM only ever recorded the third.

```
SUPPORTED   what the endpoint offered when asked      (enumeration evidence)
CONFIGURED  what policy says it should do             (configuration evidence)
NEGOTIATED  what one handshake actually produced      (handshake evidence)
```

`payments.bank.example:443` — payments.bank.example:443: supported TLS1.2, TLS1.3 (1 evidence id(s)); configured TLS1.2 (1 evidence id(s)); negotiated TLS1.3 (1 evidence id(s))

| conclusion | may it be drawn? | basis |
|---|---|---|
| a protocol is **disabled** | only from a complete authorized enumeration | `DISABLED_PROVEN`, else `NOT_ENUMERATED` / `ENUMERATION_INCOMPLETE` |
| the endpoint's **minimum** version | from configuration, then a complete enumeration | `CONFIGURED` · `SUPPORTED_ENUMERATION` · `NEGOTIATED_ONLY` (not claimable) |
| a protocol is **in use** | from a negotiated handshake | `NEGOTIATED` |
| what else the endpoint **supports** | only from an enumeration | never from a handshake |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `three_states` | are supported, configured and negotiated three answers? | **PASS** | 5, 0 failing |
| `no_inference` | can one state be inferred from another? | **PASS** | 6, 0 failing |
| `disabled_claims` | when may the platform say an old protocol is disabled? | **PASS** | 6, 0 failing |
| `minimum` | what may be called the endpoint's minimum version? | **PASS** | 5, 0 failing |
| `document` | can a document reader merge the three states by accident? | **PASS** | 5, 0 failing |

## `three_states` — PASS

*are supported, configured and negotiated three answers?* (review 7)

- **PASS** `the-review-s-three-states-are-three-state-sets` — payments.bank.example:443: supported TLS1.2, TLS1.3 (1 evidence id(s)); configured TLS1.2 (1 evidence id(s)); negotiated TLS1.3 (1 evidence id(s))
- **PASS** `every-state-carries-its-own-evidence-ids` — supported=ENUM-1, configured=CFG-1, negotiated=NET-1
- **PASS** `the-negotiated-facets-belong-to-the-handshake` — X25519 and ECDSA-P256 are negotiated facts, not offered ones
- **PASS** `a-document-s-word-for-configured-is-the-same-state` — ENABLED in a config document is CONFIGURED here
- **PASS** `an-ssh-advertised-list-is-supported-not-negotiated` — ADVERTISED → SUPPORTED, so review item 13 can use the same model

## `no_inference` — PASS

*can one state be inferred from another?* (review 7 / 3)

- **PASS** `a-negotiated-handshake-says-nothing-about-what-else-is-supported` — legacy: negotiated TLS1.2, supported unknown
- **PASS** `support-for-a-protocol-does-not-say-it-is-in-use` — TLS1.2 supported, TLS1.3 negotiated
- **PASS** `a-fact-whose-state-nobody-stated-is-refused` — state 'MAYBE' is not one of SUPPORTED, CONFIGURED, NEGOTIATED — a fact whose state is unknown cannot be sorted into one, and guessing would be the bug
- **PASS** `a-state-with-no-evidence-id-is-a-claim-and-is-refused` — a SUPPORTED fact with no evidence id is a claim: the state must be provable, not asserted
- **PASS** `a-state-fact-about-nothing-is-refused` — a NEGOTIATED fact with no protocol, suite, group or signature algorithm says nothing about the endpoint
- **PASS** `the-summary-names-the-endpoints-only-negotiation-was-seen-on` — 2 endpoint(s); 1 with a complete capability enumeration; 1 observed only by negotiation, so nothing may be claimed about what else they support

## `disabled_claims` — PASS

*when may the platform say an old protocol is disabled?* (review 3 / 7)

- **PASS** `a-complete-enumeration-proves-a-protocol-is-gone` — TLS1.1 is absent from a complete enumeration of payments.bank.example:443 (TLS1.2, TLS1.3)
- **PASS** `a-protocol-that-was-negotiated-is-not-disabled` — TLS1.3 is not proven disabled on payments.bank.example:443: TLS1.3 was negotiated, so it is not disabled
- **PASS** `a-protocol-still-offered-is-not-disabled` — TLS1.2 is not proven disabled on payments.bank.example:443: TLS1.2 is still offered by the endpoint
- **PASS** `a-modern-handshake-is-not-an-enumeration` — TLS1.1 is not proven disabled on legacy.bank.example:443: no capability enumeration was run, so 'disabled' would be an assumption: a modern handshake is not an enumeration
- **PASS** `a-partial-enumeration-cannot-speak-for-what-it-never-asked` — TLS1.2 is not proven disabled on a:443: the enumeration did not try every ClientHello variant, so the protocols that were never asked about are exactly where the old one hides
- **PASS** `an-endpoint-nobody-observed-is-unknown-not-clean` — no observation, so nothing is known

## `minimum` — PASS

*what may be called the endpoint's minimum version?* (review 7)

- **PASS** `configuration-is-the-first-basis-for-a-minimum` — policy configures TLS1.2 as the minimum on payments.bank.example:443 (1 evidence id(s))
- **PASS** `a-complete-enumeration-is-the-second-basis` — TLS1.2 is the lowest protocol a complete enumeration offered on a:443
- **PASS** `a-negotiated-version-is-never-a-minimum` — legacy.bank.example:443: the only version observed was negotiated, which describes this handshake and not the endpoint's minimum
- **PASS** `an-endpoint-nobody-observed-has-no-minimum` — no observation, so no minimum
- **PASS** `the-basis-travels-with-the-answer` — CONFIGURED · SUPPORTED_ENUMERATION · NEGOTIATED_ONLY

## `document` — PASS

*can a document reader merge the three states by accident?* (review 7 / 6)

- **PASS** `each-state-becomes-its-own-property` — ["cryptoscan:configured_evidence_id", "cryptoscan:configured_tls_version", "cryptoscan:negotiated_cipher_suite", "cryptoscan:negotiated_evidence_id"]
- **PASS** `no-merged-version-property-exists-to-be-misread` — a single tls_version property would force every reader to guess its state
- **PASS** `the-enumeration-flag-travels-with-the-endpoint` — cryptoscan:tls_enumeration_complete = true
- **PASS** `evidence-ids-travel-per-state-not-as-one-list` — supported=ENUM-1, negotiated=NET-1
- **PASS** `an-endpoint-the-model-does-not-know-is-left-alone` — other:443 is untouched

## What this does not prove

- SUPPORTED is only as complete as the enumeration behind it. The model records the flag rather than inferring it, because a scanner that tries one ClientHello has not asked the endpoint anything about old protocols
- the model holds facts, not policy quality. It can say TLS1.1 is disabled; it cannot say whether TLS1.2 is acceptable for this data classification, which is a policy judgement made elsewhere
- a configured minimum is an intent. If nothing measures the endpoint against it, the configuration is a declaration and the drift between it and what was negotiated is a separate finding
- the three states share one vocabulary across TLS, SSH and IKE, but the collectors do not exist yet for SSH and IKE. The alias table is ready; the evidence is not
- an endpoint is identified by host:port here. Two virtual hosts behind one address need SNI in the identity before their state sets can be kept apart — that is the open asset-identity item, not a solved problem
- refusals are reported per row rather than failing the batch. A single evidence-less claim does not silence the endpoints that were measured, and it does not disappear either

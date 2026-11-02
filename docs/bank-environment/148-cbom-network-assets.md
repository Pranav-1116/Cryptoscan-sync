# Network crypto assets: the interface owns the hop

`cryptoscan.cbom-network-assets-guide/1` · generated 2026-11-02T18:33:15.668626+00:00 · **6 pass · 0 partial · 0 fail** · 39 probes

Review item 8, in the review's own words: if network observes `TLS_AES_256_GCM_SHA384`, the CBOM should say *network crypto asset AES-256-GCM, endpoint payments.bank.example:443, observed on External LB, evidence NET-9281, hop Internet → External LB* — **not** *Payments API uses AES-256-GCM*, unless the evidence proves that.

```
Internet → WAF → External LB → API Gateway → Payments API
                        ^
                        the handshake terminates here
```

`cbom.network_assets` keeps the attribution:

1. **one asset per (endpoint, algorithm)** carrying `observed_on`, the hop label, the interface role and its evidence ids;
2. **no application name unless proven** — declared by the estate, or declared by the hop itself as `role: APPLICATION`. A hostname is never read as proof;
3. **the terminator is classified** — `WAF`, `LOAD_BALANCER`, `API_GATEWAY`, `REVERSE_PROXY`, `CDN`, `APPLICATION`, else `UNKNOWN`;
4. **a hop with no owner or no evidence is refused**, because "somewhere in the path" is what lets the wrong system inherit the algorithms;
5. **the overclaim is detectable** — `audit_graph` reports every `USES_CRYPTO` edge whose whole basis is a handshake that terminated in front of its subject.

On the sample path: 10 asset(s) over 3 endpoint(s) and 3 interface(s); roles `{"API_GATEWAY": 4, "APPLICATION": 4, "LOAD_BALANCER": 2}`; 10 network asset(s) over 3 endpoint(s); 4 attributed to an application, 6 left with the interface that terminated them.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `the_shape` | does an observation produce the asset the review asks for? | **PASS** | 8, 0 failing |
| `the_owner` | who does the algorithm belong to? | **PASS** | 7, 0 failing |
| `merging` | does one connection produce one asset, or a pile of rows? | **PASS** | 5, 0 failing |
| `refusals` | what is refused rather than attributed to nobody? | **PASS** | 6, 0 failing |
| `the_document` | can a reviewer read the component without guessing the hop? | **PASS** | 6, 0 failing |
| `the_audit` | is the review's overclaim detectable, or only documented? | **PASS** | 7, 0 failing |

## `the_shape` — PASS

*does an observation produce the asset the review asks for?* (review 8)

- **PASS** `the-network-asset-is-the-algorithm` — AES-256-GCM
- **PASS** `the-endpoint-is-the-one-that-negotiated-it` — payments.bank.example:443
- **PASS** `the-asset-says-which-interface-observed-it` — External LB
- **PASS** `the-evidence-id-travels-with-the-asset` — NET-9281
- **PASS** `the-hop-is-named-not-just-indexed` — Internet → External LB
- **PASS** `the-terminator-is-classified` — LOAD_BALANCER
- **PASS** `the-statement-says-who-owns-the-fact` — AES-256-GCM was negotiated on payments.bank.example:443 and observed on External LB (LOAD_BALANCER); it is an interface fact and is not attributed to any application
- **PASS** `the-tls-version-is-kept-with-the-algorithm` — 1.3

## `the_owner` — PASS

*who does the algorithm belong to?* (review 8 / 9)

- **PASS** `a-fronting-terminator-is-not-an-application` — the LB terminated the handshake; the application behind it was not observed
- **PASS** `a-declared-application-terminates-its-own-hop` — AES-128-GCM is attributed to payments-api
- **PASS** `an-undeclared-name-is-not-taken-on-trust` — a hostname that looks like an application is still a hop terminator
- **PASS** `a-hop-may-declare-itself-the-application` — role=APPLICATION is a claim the collector makes, not one this module invents
- **PASS** `the-two-hops-do-not-share-an-attribution` — the LB's AES-256-GCM and the application's AES-128-GCM are different facts
- **PASS** `the-gateway-is-not-the-application-either` — an API gateway in the middle of the path terminates its own hop
- **PASS** `the-summary-says-how-much-stayed-with-the-interface` — 10 network asset(s) over 3 endpoint(s); 4 attributed to an application, 6 left with the interface that terminated them

## `merging` — PASS

*does one connection produce one asset, or a pile of rows?* (review 8)

- **PASS** `a-repeated-observation-merges-its-evidence` — NET-9281, NET-9290
- **PASS** `a-hop-that-changed-version-keeps-both` — 1.2, 1.3
- **PASS** `two-endpoints-are-two-assets` — 4 network crypto asset(s) across 2 endpoint(s) and 1 interface(s); 4 not attributed to an application
- **PASS** `the-role-inside-the-suite-survives` — {"AES-128-GCM": "BULK", "ECDHE": "KEY_EXCHANGE", "RSA": "SIGNATURE", "SHA-256": "HASH"}
- **PASS** `an-openssl-suite-keeps-its-bulk-cipher` — ECDHE-RSA-AES128-GCM-SHA256 tokenises to AES128_GCM, which the suite table now covers

## `refusals` — PASS

*what is refused rather than attributed to nobody?* (review 8 / 12)

- **PASS** `a-hop-with-no-endpoint-is-refused` — a hop needs the endpoint where it was observed
- **PASS** `a-hop-with-no-suite-attributes-no-algorithm` — no negotiated suite, so no algorithm is attributed
- **PASS** `a-handshake-with-no-evidence-is-inventory-not-fact` — the handshake has no evidence id, so the algorithm cannot be attributed to anything
- **PASS** `a-path-position-is-not-an-owner` — no interface is recorded as having observed the handshake; a path position is not an owner
- **PASS** `a-hop-that-is-not-an-object-is-refused` — a hop must be an object
- **PASS** `the-hop-target-is-used-when-no-observer-was-recorded` — a hop that names its target names its terminator

## `the_document` — PASS

*can a reviewer read the component without guessing the hop?* (review 8 / 12)

- **PASS** `one-component-per-endpoint-and-algorithm` — 10 component(s) for 10 asset(s)
- **PASS** `the-component-is-a-cyclonedx-cryptographic-asset` — network:payments.bank.example:443#AES-256-GCM
- **PASS** `the-five-fields-are-carried-as-properties` — {"cryptoscan:endpoint": "payments.bank.example:443", "cryptoscan:evidence_id": "NET-9281", "cryptoscan:hop": "Internet \u2192 External LB", "cryptoscan:observed_on": "External LB"}
- **PASS** `no-application-is-written-where-none-was-proven` — the LB component names the interface, not the application
- **PASS** `a-proven-application-is-written-down` — network:payments-api.internal:8443#AES-128-GCM
- **PASS** `the-network-level-is-on-the-component` — a network observation promotes to NETWORK, not to VERIFIED

## `the_audit` — PASS

*is the review's overclaim detectable, or only documented?* (review 8 / 20)

- **PASS** `an-application-edge-resting-on-a-fronting-hop-is-an-overclaim` — 1 overclaim(s) among 1 network-backed USES_CRYPTO edge(s); each rests on a hop that terminated in front of the subject
- **PASS** `the-overclaim-carries-the-role-that-terminated-it` — LOAD_BALANCER
- **PASS** `a-system-edge-is-audited-too` — an estate-level claim is the same claim, one level up
- **PASS** `an-edge-with-runtime-evidence-is-not-an-overclaim` — the application was observed doing it; the handshake is corroboration
- **PASS** `an-algorithm-the-network-never-saw-is-not-audited` — no network asset, no network claim
- **PASS** `another-edge-kind-is-not-a-usage-claim` — NEGOTIATES is the endpoint's, not a use
- **PASS** `the-estate-chain-exposes-the-audit` — 2 overclaim(s) among 2 network-backed USES_CRYPTO edge(s); each rests on a hop that terminated in front of the subject

## What this does not prove

- the identification of a hop's role is a name heuristic plus whatever the collector declares. A load balancer called 'edge01' is UNKNOWN here, which is the honest answer and also an operational gap: the collector should report a role rather than a hostname
- the module cannot see the path. It attributes each hop by itself; a hop whose 'from' is wrong, or a probe that went through a CDN the operator did not record, produces a correct attribution for the wrong topology
- an application is proven by declaration, not by observation. Declaring the wrong set of applications turns NOT_PROVEN into PROVEN, and the audit will then be silent about a real overclaim
- the audit only sees a graph it is given. A report that never builds a USES_CRYPTO edge cannot overclaim here, and equally cannot be checked here
- network evidence proves what was negotiated, not what is enforced: a suite offered in a handshake says nothing about the algorithms the application uses on the data afterwards
- a certificate's public key algorithm arrives as its own evidence category. ECDSA-P256 in a certificate is the certificate's, and this module deliberately never turns it into an application algorithm
- one endpoint may front several applications through SNI; without per-SNI probing the hop is one asset, and the mapping to applications stays unproven

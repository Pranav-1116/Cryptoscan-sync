# Agent machine identity — certificate → agent → signed observation

`cryptoscan.agent-identity/1` · generated 2026-11-01T04:42:28.695279+00:00 · **7 pass · 0 partial · 0 fail**

| Question | Verdict | Evidence |
|---|---|---|
| **can the boundary read the identity the TLS handshake proved?** | **PASS** | real TLS handshake: the server's getpeercert produced SPKI sha256:95b711837740b5ff81ee02f48c3a5c09e99606e5bad75c4f28702990a540de90 |
| **is an unregistered certificate refused?** | **PASS** | lookup returned agent-eu-1 |
| **must the signature be the key registered for that agent?** | **PASS** | signature key matches the key registered for agent agent-eu-1 |
| **does the middleware refuse an ingest request with no registered agent?** | **PASS** | middleware admitted the request with status 200 |
| **does the ingestion route refuse a signature that is not the agent's?** | **PASS** | accepted |
| **does certificate → agent → signature hold, and does the replay fail?** | **PASS** | certificate→agent agent-eu-1, signature bound, authenticity VALID |
| **can each instrument fail?** | **PASS** | a deliberately wrong key is reported as unbound: signature key 5c29b78f10a35a49… is not the key registered for agent agent-eu-1 |

## Row by row

### `certificate_readable` — PASS

*can the boundary read the identity the TLS handshake proved?*

- **PASS** `server-reads-peer-certificate` — real TLS handshake: the server's getpeercert produced SPKI sha256:95b711837740b5ff81ee02f48c3a5c09e99606e5bad75c4f28702990a540de90
- **PASS** `fingerprint-is-the-key-not-the-certificate` — the SPKI fingerprint is computed from the public key, so reissuing a certificate for the same key keeps the identity and a new key never inherits an old one
- **Limit:** the drill reads the certificate from a socketpair handshake; whether the deployed server exposes it to the application depends on the terminator (see agent_identity.peer_certificate)

### `registry` — PASS

*is an unregistered certificate refused?*

- **PASS** `registered-fingerprint-resolves` — lookup returned agent-eu-1
- **PASS** `fingerprint-normalisation` — an upper-case, colon-separated fingerprint resolves to the same agent as the canonical form
- **PASS** `unregistered-fingerprint-refused` — a certificate from the same CA that is not in the registry resolves to no agent
- **PASS** `duplicate-fingerprint-refused` — refused: two agents share the fingerprint sha256:95b711837740b5ff81ee02f48c3a5c09e99606e5bad75c4f28702990a540de90
- **PASS** `malformed-registry-fails-closed` — refused: agent entry 0 is missing signing_key
- **PASS** `empty-registry-refuses-everything` — with no agents registered, no certificate resolves — the default is refusal, not trust

### `signature_binding` — PASS

*must the signature be the key registered for that agent?*

- **PASS** `bound-key-accepted` — signature key matches the key registered for agent agent-eu-1
- **PASS** `foreign-key-refused` — signature key 34750f98bd59fcfc… is not the key registered for agent agent-eu-1
- **PASS** `unsigned-observation-refused` — agent agent-eu-1 presented the certificate but the observation carries no signature, so nothing binds the payload to that machine
- **PASS** `swapped-embedded-key-refused` — signature key c62e4615bd39e222… is not the key registered for agent agent-eu-1

### `http_enforcement` — PASS

*does the middleware refuse an ingest request with no registered agent?*

- **PASS** `registered-certificate-admitted` — middleware admitted the request with status 200
- **PASS** `unusable-certificate-refused` — unusable certificate answered 403
- **PASS** `no-certificate-refused` — a request with no peer certificate answered 403
- **PASS** `non-ingest-surface-unaffected` — a non-ingest path answered 200 with no certificate
- **PASS** `inert-when-not-required` — with the requirement off (the default) the middleware changes nothing, so this is an opt-in deployment property
- **PASS** `declared-terminator-fingerprint-refused-when-unregistered` — a forwarded fingerprint is not trusted by itself: the registry still decides

### `route_binding` — PASS

*does the ingestion route refuse a signature that is not the agent's?*

- **PASS** `route-accepts-bound-signature` — accepted
- **PASS** `route-refuses-foreign-signature` — {"error": "signature_not_bound_to_agent", "agent_id": "agent-eu-1", "reason": "signature key c5b940ed3f65c391\u2026 is not the key registered for agent agent-eu
- **PASS** `route-refuses-unsigned` — {"error": "signature_not_bound_to_agent", "agent_id": "agent-eu-1", "reason": "agent agent-eu-1 presented the certificate but the observation carries no signatu
- **PASS** `route-refuses-without-identity` — {"error": "agent_identity_unregistered", "reason": "no certificate", "stored": false}
- **PASS** `route-inert-when-not-required` — with the requirement off the route keeps its previous behaviour, which is why this is a deployment property

### `end_to_end` — PASS

*does certificate → agent → signature hold, and does the replay fail?*

- **PASS** `honest-chain` — certificate→agent agent-eu-1, signature bound, authenticity VALID
- **PASS** `replay-with-another-agents-signature-refused` — signature key 72456720412037a6… is not the key registered for agent agent-eu-1

### `controls` — PASS

*can each instrument fail?*

- **PASS** `control-binding-detects-a-mismatch` — a deliberately wrong key is reported as unbound: signature key 5c29b78f10a35a49… is not the key registered for agent agent-eu-1
- **PASS** `control-garbage-certificate-rejected` — refused: not a usable certificate: error parsing asn1 value: ParseError { kind: ShortData { needed: 75 } }
- **PASS** `control-registry-lookup-of-unknown-is-none` — an unknown fingerprint returns None rather than a default identity

## What this does not prove

- The SPKI fingerprint is the identity. A machine that can export its key is that machine to this platform; the private key is the credential and hardware-backed keys are the deployment's choice.
- The registry is a deployment file. Who may write it is a control the platform does not own — that is the same trust the certificate authority already has.
- Whether the TLS server in front of the API exposes its peer certificate to the application is a terminator property; the drill proves the application half and names the dependency rather than assuming it.

**The verdict this drill supports:** the certificate a client presents is read at the boundary, resolves to a registered agent or to nothing, and an observation is accepted only when its signature is the key registered for the agent the certificate proved — so the three facts guide 119 called independent are now one chain, and the replay that separated them is refused.

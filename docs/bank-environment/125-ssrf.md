# SSRF — policy, then the four ways around a policy

`cryptoscan.ssrf/1` · generated 2026-11-01T04:50:57.142931+00:00 · **6 pass · 0 partial · 0 fail** · 18 probes

| Question | Verdict | Evidence |
|---|---|---|
| **is the target of a collection authorized by the server, not by the caller's role?** | **PASS** | 409 {"detail":{"error":"scope_not_configured","reason":"no approved network scope — CryptoScan refuses to probe until a scope names the exact destinations"}} |
| **does the runtime egress guard refuse an outbound connection?** | **PASS** | refused before a socket existed: outbound connection to 169.254.169.254:80 denied: not in egress allowlist (0 rules) |
| **can an approved name be re-pointed at a private address?** | **PASS** | outbound connection to collector.example:443 denied: resolved to an address that was not authorised when the allowlist was installed (possible DNS rebinding: 127.0.0.1) |
| **is a redirect to an unapproved destination followed?** | **PASS** | urllib followed the redirect to the internal service: 200 ok |
| **does a hand-built socket bypass the guard?** | **PASS** | outbound connection to 10.20.10.15:443 denied: direct socket connect to a destination outside the egress allowlist |
| **does the guard still allow what it should?** | **PASS** | 200 ok |

## Row by row

### `target_policy` — PASS

*is the target of a collection authorized by the server, not by the caller's role?*

- **PASS** `no-scope-fails-closed` — 409 {"detail":{"error":"scope_not_configured","reason":"no approved network scope — CryptoScan refuses to probe until a scope names the exact destinations"}}
- **PASS** `scope-rejects-cidr` — 422 {"detail":{"error":"invalid_destination","reason":"probe_target[0]: malformed probe hostname: '10.0.0.0/8'"}}
- **PASS** `scope-rejects-metadata` — 422 {"detail":{"error":"invalid_destination","reason":"probe_target[0]: refusing to probe loopback/cloud-metadata target"}}
- **PASS** `scope-rejects-loopback` — 422 {"detail":{"error":"invalid_destination","reason":"probe_target[0]: refusing to probe 127.0.0.1 — loopback/metadata/multicast/reserved blocked"}}
- **PASS** `scope-accepted` — 200 {"inventory_id":"default","scope":{"name":"drill-scope","type":"network","destinations":["10.20.10.15:443"],"protocols":["TLS"],"allowed_operations":["CONNECT","TLS_HANDSHAKE","CERTIFICATE_READ"],"tra
- **PASS** `out-of-scope-host-refused` — 409 {"detail":{"error":"destination_outside_scope","reason":"1 destination(s) outside the approved scope","outside":["10.20.10.99:443"],"approved":["10.20.10.15:443"]}}
- **PASS** `cidr-in-request-refused` — 409 {"detail":{"error":"destination_outside_scope","reason":"1 destination(s) outside the approved scope","outside":["10.20.10.0/24:443"],"approved":["10.20.10.15:443"]}}
- **PASS** `source-root-refused` — 400 {"detail":"repo_url: source path /etc is outside the allowed source roots"}
- **Not proven:** which hosts a bank has *approved* is deployment data; this row proves the refusal paths, not that a given CIDR list is the right one
- **Limit:** this is guide 121's target row re-executed in this drill so the SSRF report stands on its own; the matrix per collector is guide 116

### `runtime_guard` — PASS

*does the runtime egress guard refuse an outbound connection?*

- **PASS** `empty-allowlist-blocks-everything` — refused before a socket existed: outbound connection to 169.254.169.254:80 denied: not in egress allowlist (0 rules)
- **PASS** `explicit-allowlist-is-honoured` — an operator who allowlists an address means it: the rule is applied as written (the drill does not pretend the platform second-guesses them)

### `dns_rebinding` — PASS

*can an approved name be re-pointed at a private address?*

- **PASS** `rebinding-to-loopback-refused` — outbound connection to collector.example:443 denied: resolved to an address that was not authorised when the allowlist was installed (possible DNS rebinding: 127.0.0.1)
- **PASS** `name-with-no-pinned-address-refused` — outbound connection to unresolvable.invalid:443 denied: name was not resolvable when the allowlist was installed, so it has no pinned address

### `redirects` — PASS

*is a redirect to an unapproved destination followed?*

- **PASS** `control-redirect-is-followed-without-the-guard` — urllib followed the redirect to the internal service: 200 ok
- **PASS** `redirect-to-unapproved-host-refused` — 0 EgressBlocked: outbound connection to 127.0.0.1:40459 denied: not in egress allowlist (1 rules)
- **PASS** `redirect-to-metadata-address-refused` — 0 EgressBlocked: outbound connection to 169.254.169.254:80 denied: not in egress allowlist (1 rules)
- **Limit:** the drill's redirect target is a local service standing in for cloud metadata; the address refused in the second probe is the real 169.254.169.254

### `direct_sockets` — PASS

*does a hand-built socket bypass the guard?*

- **PASS** `direct-socket-connect-refused` — outbound connection to 10.20.10.15:443 denied: direct socket connect to a destination outside the egress allowlist

### `controls` — PASS

*does the guard still allow what it should?*

- **PASS** `allowlisted-destination-still-works` — 200 ok
- **PASS** `control-without-guard-still-works` — 200 ok
- **Limit:** the guard covers socket-level egress in this process. A collector that shells out (git, ssh, docker) makes its own connections and is covered by guide 122's argument analysis and by deployment egress policy, not by this module

## What this does not prove

- UDP (sendto), raw sockets and direct syscalls are outside a Python-level guard; deployment egress policy is the control for those.
- The guard is off unless EGRESS_GUARD=enforce, so the protection described here is a deployment property, proved rather than assumed.

**The verdict this drill supports:** a collector target is authorized server-side before anything is collected, and once a target is approved the runtime guard still refuses an outbound connection to anything else — including a redirect and a name that rebinds to loopback after approval.

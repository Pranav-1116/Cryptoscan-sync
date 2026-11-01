# Authorization boundaries — declared versus enforced

`cryptoscan.authorization-boundaries/1` · generated 2026-11-01T03:08:21.481861+00:00 · **8 pass · 1 partial · 0 fail** · 1225 operations, 1617 decisions executed

For every operation that declares a boundary, the drill resolves the roles the declaration allows, then sends the request as Admin, Auditor and Viewer through the real app. A decision that disagrees with the declaration is a violation.

| Question | Verdict | Evidence |
|---|---|---|
| **are Admin, Auditor and Viewer distinct identities with distinct authority?** | **PASS** | normalize_roles(['admin']) = ['superadmin'] |
| **can a admin (superadmin) cross into authority it does not hold?** | **PASS** | 0 escape(s) |
| **can a auditor (auditor) cross into authority it does not hold?** | **PASS** | 0 escape(s) |
| **can a viewer (readonly) cross into authority it does not hold?** | **PASS** | 0 escape(s) |
| **does what the route declares match what the server enforces?** | **PASS** | 1617 decisions, 0 violating, 9 over-tight |
| **is the boundary enforced without a session, or is it a UI convention?** | **PASS** | 0 of 562 gated writes answered without a token |
| **does a token claiming superadmin, signed elsewhere, get in?** | **PASS** | 0 write(s) accepted a foreign-signed token |
| **which state-changing operations demand nothing beyond a session?** | **PARTIAL** | 180 of 562 gated writes are session-only |
| **is the target of a collection authorized by the server, not by the caller's role?** | **PASS** | 409 {"detail":{"error":"scope_not_configured","reason":"no approved network scope — CryptoScan refuses to probe until a scope names the exact destinations"}} |

## Row by row

### `role_catalog` — PASS

*are Admin, Auditor and Viewer distinct identities with distinct authority?*

- **PASS** `role-superadmin` — admin resolves to superadmin in the catalog: normalize_roles(['admin']) = ['superadmin']
- **PASS** `role-auditor` — auditor resolves to auditor in the catalog: normalize_roles(['auditor']) = ['auditor']
- **PASS** `role-readonly` — viewer resolves to readonly in the catalog: normalize_roles(['viewer']) = ['readonly']
- **PASS** `permissions-are-nested` — viewer ⊂ auditor ⊂ admin: 4 / 13 / 36 permissions

### `boundary_superadmin` — PASS

*can a admin (superadmin) cross into authority it does not hold?*

- **PASS** `no-escape` — no operation allowed that the declaration forbids: 0 escape(s)
- **PASS** `boundary-is-real` — every forbidden operation probed is refused: 0 of 0 forbidden operations refused

### `boundary_auditor` — PASS

*can a auditor (auditor) cross into authority it does not hold?*

- **PASS** `no-escape` — no operation allowed that the declaration forbids: 0 escape(s)
- **PASS** `boundary-is-real` — every forbidden operation probed is refused: 188 of 188 forbidden operations refused

### `boundary_readonly` — PASS

*can a viewer (readonly) cross into authority it does not hold?*

- **PASS** `no-escape` — no operation allowed that the declaration forbids: 0 escape(s)
- **PASS** `boundary-is-real` — every forbidden operation probed is refused: 286 of 286 forbidden operations refused

### `declared_vs_enforced` — PASS

*does what the route declares match what the server enforces?*

- **PASS** `matrix-agrees` — every executed decision matches the declared requirement: 1617 decisions, 0 violating, 9 over-tight
- **PASS** `comparator-can-fail` — the comparison reports a decision the declaration forbids, and only that: a viewer allowed on a superadmin-only permission is reported; the superadmin on the same permission is not
- **Not proven:** over-tight guards refuse a role the declaration allows; see over_tight
- **Not provoked:** `POST /api/v1/auth/me/sessions/revoke` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/auth/users/{username}/restore` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/certificates/{fingerprint}/revoke` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/control/credentials/{credential_id}/rotate` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/control/safe-scan/emergency-stop` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/exceptions/{exception_id}/revoke` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/findings/{evidence_id}/restore` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/live-scan/stop` — destructive; declaration read, request not sent
- **Not provoked:** `GET /api/v1/network/crypto-safety` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/network/crypto-stop` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/resilience/backup/restore` — destructive; declaration read, request not sent
- **Not provoked:** `POST /api/v1/saas/admin/tenants/{tenant_id}/restore` — destructive; declaration read, request not sent

### `anonymous_refused` — PASS

*is the boundary enforced without a session, or is it a UI convention?*

- **PASS** `no-token-on-writes` — every state-changing operation refuses an unauthenticated caller: 0 of 562 gated writes answered without a token
- **Limit:** public-by-design paths (login, register, webhooks) are exempted by the gate and are guide 120's subject

### `forged_credentials` — PASS

*does a token claiming superadmin, signed elsewhere, get in?*

- **PASS** `foreign-signature` — a token signed by another deployment is refused: 0 write(s) accepted a foreign-signed token
- **Limit:** forgery with the real signing key is out of reach by definition; the key's custody is not measured here

### `session_only_writes` — PARTIAL

*which state-changing operations demand nothing beyond a session?*

- **PASS** `counted` — the count is reported rather than assumed zero: 180 of 562 gated writes are session-only
- **Not proven:** 180 write operation(s) are callable by any authenticated principal, including a viewer; the owner list is docs/bank-environment/102-authenticated-only-writes.json
- **Limit:** this row is a policy question, not a defect: it is reported so a bank can decide per area, which is the review's own framing
- **Limit:** 228 operation(s) are gated by tenant membership (owner/admin within an organisation) rather than a catalog role; those are excluded from the matrix comparison and measured by the tenancy drill

| Area | Session-only writes |
|---|---|
| `estate` | 24 |
| `network` | 24 |
| `migrations` | 13 |
| `vendors` | 10 |
| `graph` | 9 |
| `banking` | 8 |
| `cbom` | 8 |
| `systems` | 8 |
| `security` | 7 |
| `technology-bom` | 7 |
| `auth` | 6 |
| `cloud` | 6 |

### `target_authorization` — PASS

*is the target of a collection authorized by the server, not by the caller's role?*

- **PASS** `no-scope-fails-closed` — refused (409/422) with no approved scope: 409 {"detail":{"error":"scope_not_configured","reason":"no approved network scope — CryptoScan refuses to probe until a scope names the exact destinations"}}
- **PASS** `scope-rejects-cidr` — 422 when the approved scope names a /8: 422 {"detail":{"error":"invalid_destination","reason":"probe_target[0]: malformed probe hostname: '10.0.0.0/8'"}}
- **PASS** `scope-rejects-metadata` — 422 when the scope names 169.254.169.254: 422 {"detail":{"error":"invalid_destination","reason":"probe_target[0]: refusing to probe loopback/cloud-metadata target"}}
- **PASS** `scope-rejects-loopback` — 422 when the scope names 127.0.0.1: 422 {"detail":{"error":"invalid_destination","reason":"probe_target[0]: refusing to probe 127.0.0.1 — loopback/metadata/multicast/reserved blocked"}}
- **PASS** `scope-accepted` — 2xx for one exact host:port: 200 {"inventory_id":"default","scope":{"name":"drill-scope","type":"network","destinations":["10.20.10.15:443"],"protocols":["TLS"],"allowed_operations":["CONNECT","TLS_HANDSHAKE","CERTIFICATE_READ"],"tra
- **PASS** `out-of-scope-host-refused` — refused for a host outside the approved scope: 409 {"detail":{"error":"destination_outside_scope","reason":"1 destination(s) outside the approved scope","outside":["10.20.10.99:443"],"approved":["10.20.10.15:443"]}}
- **PASS** `cidr-in-request-refused` — refused for a CIDR in the request itself: 409 {"detail":{"error":"destination_outside_scope","reason":"1 destination(s) outside the approved scope","outside":["10.20.10.0/24:443"],"approved":["10.20.10.15:443"]}}
- **PASS** `source-root-refused` — 4xx for a target outside CRYPTOSCAN_SOURCE_ROOTS: 400 {"detail":"repo_url: source path /etc is outside the allowed source roots"}
- **Not proven:** which hosts a bank has *approved* is deployment data; this row proves the refusal paths, not that a given CIDR list is the right one
- **Limit:** the per-collector matrix for these questions is guide 116
- **Limit:** the traffic budget and window are measured by guide 116's probes

## What this does not prove

- Executed in-process against the real app and a temporary SQLite database. Authorization decisions are the server's own; what is not proven is the deployment around it (reverse proxy, identity provider, network policy).
- A permitted request is not a completed one: this drill asks whether the guard let the caller through, not whether the handler then did something useful. A 5xx past the guard still counts as past the boundary.
- Empty request bodies mean body-level validation is not exercised; tenant isolation is a separate drill (guide 124).

**The verdict this drill supports:** where a boundary is declared, the server enforces it — a Viewer cannot write, an Auditor cannot administer, an Admin cannot aim a collector at a CIDR or at the metadata address, and none of the three can reach a write without a session or with a token signed elsewhere. What it also says, plainly, is how much of the write surface declares nothing at all; that is a policy decision for the bank, not something this drill can grade.

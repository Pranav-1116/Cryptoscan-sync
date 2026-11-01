# Secret management — canaries through four paths

`cryptoscan.secret-management/1` · generated 2026-11-01T03:54:17.222681+00:00 · **3 pass · 2 partial · 1 fail**

| Question | Verdict | Evidence |
|---|---|---|
| **is a credential committed to the tree?** | **PASS** | 0 finding(s) across 7 patterns; 13 allow-listed with a stated reason |
| **does a secret written to a log come back out?** | **PARTIAL** | canary absent: password/api_token/private_key were masked |
| **can a failing call return a credential to the caller?** | **PASS** | canary absent from the 500 body |
| **does the request log record the credential it was given?** | **PASS** | the access line was written and carries none of the three |
| **does the console keep a session where a script on the page can read it?** | **FAIL** | 1 storage write(s) of a credential-shaped key |
| **does a credential travel in a query string?** | **PARTIAL** | 1 query-string credential(s) |

## Row by row

### `source_scan` — PASS

*is a credential committed to the tree?*

- **PASS** `no-live-credential` — 0 finding(s) across 7 patterns; 13 allow-listed with a stated reason
- **Allow-listed:** `scripts/coverage.sh:39` (credential_literal) — test-only environment values, exported under ENVIRONMENT=test
- **Allow-listed:** `scripts/golden_path.py:272` (aws_access_key) — the AWS documentation example key AKIAIOSFODNN7EXAMPLE, used by a local harness
- **Allow-listed:** `scripts/secret_management.py:68` (aws_access_key) — this drill: the allow-list reasons quote the example key they excuse
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:991` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:992` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:993` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:994` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:1008` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:1009` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:1010` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/devsecops/devsecops/yara_rules.py:1011` (private_key_block) — YARA detector: these are the strings the rule *looks for*, not key material
- **Allow-listed:** `services/eventstream/eventstream/bus.py:27` (credential_literal) — development stream key; the constructor raises in production when STREAM_SECRET is unset or still this value
- **Allow-listed:** `services/eventstream/eventstream/livecbom.py:26` (credential_literal) — development CBOM signing key; the constructor raises in production when CBOM_SIGNING_SECRET is unset or still this value
- **Not proven:** a secret that matches no pattern (a bare high-entropy string) is not found by this scan; entropy scanning produces enough noise here to be switched off rather than tuned to pass

### `log_redaction` — PARTIAL

*does a secret written to a log come back out?*

- **PASS** `structured-field` — canary absent: password/api_token/private_key were masked
- **NOT MET** `free-text-message` — canary present: redaction is key-based, so a secret written into the message text is not scrubbed
- **PASS** `control-redaction-off` — canary visible
- **Not proven:** redaction is key-based: a secret interpolated into the message text is written verbatim. The mitigation is a rule (never interpolate a credential) and a log-side pattern scrub, neither of which is in place yet
- **Limit:** measured through the configured handler in-process; the behaviour of a collector agent's own log shipper is its own

### `error_messages` — PASS

*can a failing call return a credential to the caller?*

- **PASS** `unhandled-exception-body` — canary absent from the 500 body
- **PASS** `explicit-detail` — control: a hand-written detail is returned verbatim, so the check above is not passing because responses are empty
- **Limit:** the application's own handlers are the subject of guide 120's rows; this row asks what an unhandled driver error and a hand-written detail put on the wire

### `access_log` — PASS

*does the request log record the credential it was given?*

- **PASS** `access-line-has-no-credential` — the access line was written and carries none of the three
- **Not proven:** an upstream proxy's own access log is outside this drill

### `frontend_storage` — FAIL

*does the console keep a session where a script on the page can read it?*

- **NOT MET** `no-token-in-web-storage` — 1 storage write(s) of a credential-shaped key
- **Storage write:** `frontend/src/pages/Resilience.tsx: zelnx_token`
- **Not proven:** the built bundle is not scanned: this reads `frontend/src`, and a vendored dependency could still write to storage at runtime
- **Limit:** The backend also sets an httpOnly `cryptoscan_session` cookie and verifies the session with GET /api/v1/auth/me, so the localStorage copy is redundant as well as exposed. Removing it means making lib/api.ts hold the token in memory and letting the cookie carry the session across a reload.

### `url_token` — PARTIAL

*does a credential travel in a query string?*

- **NOT MET** `no-token-in-url` — 1 query-string credential(s)
- **URL credential:** `frontend/src/pages/InviteAccept.tsx: ?token=`
- **Limit:** The hit is `/?token=` on the invite-acceptance page: a one-time `csi_…` invitation token is read from the URL by design. It lands in browser history and in any Referer header sent from that page, and the token is single-use and server-revocable, which is why this is PARTIAL and not FAIL. A POST body would remove the exposure.

## What this does not prove

- The canary proves a specific path does not echo a specific string. It cannot prove that some other path — a queue payload, a crash dump, a support bundle — does not.
- Source scanning is pattern-based; a credential with no recognisable shape is invisible to it.

**What this drill supports:**

- is a credential committed to the tree? — answered, evidence above.
- can a failing call return a credential to the caller? — answered, evidence above.
- does the request log record the credential it was given? — answered, evidence above.

**What it does not support (and should not be quoted as if it did):**

- **PARTIAL** — does a secret written to a log come back out? canary present: redaction is key-based, so a secret written into the message text is not scrubbed
- **FAIL** — does the console keep a session where a script on the page can read it? 1 storage write(s) of a credential-shaped key
- **PARTIAL** — does a credential travel in a query string? 1 query-string credential(s)

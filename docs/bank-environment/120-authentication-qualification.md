# Authentication — eight questions, answered by execution

`cryptoscan.authentication-qualification/1` · generated 2026-11-01T05:14:46.398234+00:00 · **8 pass · 0 partial · 0 fail** · 79 probes

Each row drives the real auth router, the real session manager and the real user store through the production session gate. A row is `PASS` only when every probe produced the status it was supposed to; `PARTIAL` means everything passed but a named property was not exercised; `FAIL` means a probe answered wrong.

| Question | Verdict | Probes |
|---|---|---|
| **does a correct credential mint a session, and a wrong one never?** | **PASS** | 6/6 |
| **does the session token mean what it claims, and nothing more?** | **PASS** | 8/8 |
| **does the second factor exist, and can the first factor alone bypass it?** | **PASS** | 14/14 |
| **does a session end when it says it will?** | **PASS** | 8/8 |
| **can a session be ended before it expires, and does the gate honour it?** | **PASS** | 7/7 |
| **is a weak password refused, and is what is stored unusable?** | **PASS** | 19/19 |
| **does repeated failure lock the account, and does the lock survive a restart?** | **PASS** | 8/8 |
| **does a credential leak into a response, a URL or a log?** | **PASS** | 9/9 |

## Row by row

### `login` — PASS

*does a correct credential mint a session, and a wrong one never?*

| Probe | Expected | Result |
|---|---|---|
| `valid-credentials` | 200 with a session token | PASS (observed 200) |
| `valid-credentials-token` | a token is returned | PASS (observed True) |
| `wrong-password` | 401 | PASS (observed 401) |
| `no-user-enumeration` | unknown user and wrong password answer identically | PASS (observed (401, True)) |
| `control-mismatch-detected` | a deliberately wrong expectation is refused | PASS (mismatch reported for 401 != 200) |
| `empty-password` | no session for an empty password | PASS (observed (True, False)) |
- **Limit:** no TLS and no reverse proxy in the harness: transport security of the credential is guide 125's subject, not this row's

### `session_token` — PASS

*does the session token mean what it claims, and nothing more?*

| Probe | Expected | Result |
|---|---|---|
| `token-accepted` | 200 through the session gate | PASS (observed 200) |
| `identity-established` | the gate names the same user | PASS (observed 'admin') |
| `tampered-payload` | 401 on a modified payload | PASS (observed 401) |
| `foreign-key` | 401 for a token signed by another deployment | PASS (observed 401) |
| `missing-token` | 401 with no credential | PASS (observed 401) |
| `garbage-token` | 401 for a non-token | PASS (observed 401) |
| `role-header-ignored` | a role header does not change the identity | PASS (observed 200) |
| `cookie-flags` | session cookie is HttpOnly and SameSite | PASS (observed (True, True)) |
- **Limit:** token transport (secure cookie flag, TLS) depends on deployment config

### `mfa` — PASS

*does the second factor exist, and can the first factor alone bypass it?*

| Probe | Expected | Result |
|---|---|---|
| `enroll` | a pending TOTP secret is issued | PASS (observed 200) |
| `enroll-secret` | the secret is a base32 string | PASS (observed True) |
| `enable` | a correct code activates MFA | PASS (observed 200) |
| `recovery-codes` | recovery codes are returned once | PASS (observed 10) |
| `password-alone` | no session token when MFA is enabled | PASS (observed (200, '', True)) |
| `challenge-not-a-session` | the challenge token is not accepted as a session | PASS (observed 401) |
| `wrong-code` | 401 for a wrong TOTP | PASS (observed 401) |
| `correct-code` | 200 and a session for the right TOTP | PASS (observed 200) |
| `second-factor-session` | the issued token works at the gate | PASS (observed 200) |
| `code-single-use-first` | an unused valid code is accepted | PASS (observed 200) |
| `code-replay-refused` | the same code presented twice is refused | PASS (observed 401) |
| `code-replay-says-why` | the refusal names reuse rather than a bad code | PASS (observed True) |
| `stale-step-refused` | a code from an already-consumed step is refused | PASS (observed 401) |
| `recovery-code` | a recovery code is accepted once | PASS (observed 200) |
- **Limit:** TOTP is the only second factor the product implements: WebAuthn and IdP push are not features here, so there is nothing to exercise. The row proves the first factor alone cannot pass the gate; it does not claim a phishing-resistant authenticator exists
- **Limit:** the challenge is validated by the same session key as the session; an attacker with the signing key can forge both

### `expiry` — PASS

*does a session end when it says it will?*

| Probe | Expected | Result |
|---|---|---|
| `expired-session` | 401 once the session has expired | PASS (observed 401) |
| `live-session` | a session inside its window is accepted | PASS (observed 200) |
| `expiry-claim` | the token carries an expiry | PASS (observed True) |
| `expiry-horizon` | expiry is inside the configured window | PASS (observed True) |
| `mfa-challenge-purpose` | an MFA challenge is not a session | PASS (observed None) |
| `idle-session-refused` | a session unused past the idle window is refused | PASS (observed 401) |
| `fresh-session-accepted` | a session used now is still accepted | PASS (observed 200) |
| `idle-clock-advances` | a used session's idle clock moves forward | PASS (observed True) |
- **Limit:** all roles share one absolute lifetime (SESSION_EXPIRE_HOURS); per-role lifetime is a policy option this product does not implement

### `revocation` — PASS

*can a session be ended before it expires, and does the gate honour it?*

| Probe | Expected | Result |
|---|---|---|
| `before-logout` | the token works | PASS (observed 200) |
| `logout` | logout is accepted | PASS (observed True) |
| `after-logout` | the same token is refused after logout | PASS (observed 401) |
| `revocation-is-stored` | a second client sees the same revocation state | PASS (observed 200) |
| `revocation-crosses-clients` | the revoke is visible to the first client too | PASS (observed 401) |
| `revoke-all` | revoke-all is accepted | PASS (observed 200) |
| `revoke-all-effect` | another session for the same user stops working | PASS (observed 401) |
- **Limit:** revocation reads the session store on every request; a store outage is fail-closed in production, which is a availability trade this row does not measure

### `password_policy` — PASS

*is a weak password refused, and is what is stored unusable?*

| Probe | Expected | Result |
|---|---|---|
| `weak-short` | 422 for a too-short password | PASS (observed 422) |
| `weak-variety` | 422 for a single-class password | PASS (observed 422) |
| `self-service-privilege` | 403 when public registration asks for a privileged role | PASS (observed 403) |
| `strong-accepted` | 201 for a strong password | PASS (observed 201) |
| `hash-scheme` | the stored credential is PBKDF2, never plaintext | PASS (observed 'pbkdf2_sha256') |
| `plaintext-absent` | the plaintext is not in the stored value | PASS (observed False) |
| `hash-verifies` | the stored hash verifies the password | PASS (observed True) |
| `plaintext-fallback-refused` | a plaintext stored secret never verifies in production | PASS (observed False) |
| `identity-in-password` | 422 when the password contains the username | PASS (observed 422) |
| `rotation-accepted` | a fresh strong password is accepted | PASS (observed 200) |
| `history-blocks-reuse` | 422 when cycling back to a previous password | PASS (observed 422) |
| `history-says-why` | the refusal names reuse | PASS (observed True) |
| `history-stores-hashes` | the remembered entries are hashes, never plaintext | PASS (observed False) |
| `corpus-loaded` | a supplied corpus is parsed (digest and digest:count forms) | PASS (observed (True, 2)) |
| `breached-refused` | 422 for a strong-shaped password in the corpus | PASS (observed 422) |
| `breached-says-why` | the refusal names the corpus | PASS (observed True) |
| `unlisted-accepted` | a password absent from the corpus is accepted | PASS (observed 201) |
| `gap-announced` | production without a corpus reports a named gap | PASS (observed True) |
| `gap-not-dev-only` | the gap is scoped to production | PASS (observed None) |
- **Limit:** the corpus is operator-supplied: this drill proves the check works when a corpus is configured, not that any particular list is current — keeping the feed fresh is an operational obligation

### `lockout` — PASS

*does repeated failure lock the account, and does the lock survive a restart?*

| Probe | Expected | Result |
|---|---|---|
| `failures-refused` | every failed attempt is 401 | PASS (observed {401}) |
| `locked-with-right-password` | the correct password is refused while locked | PASS (observed 401) |
| `lock-message` | the refusal says the account is locked | PASS (observed True) |
| `lock-is-stored` | a fresh service object still refuses the account | PASS (observed True) |
| `lock-is-per-account` | a lock on one account does not lock the platform | PASS (observed 200) |
| `audited` | the failures are in the audit trail | PASS (observed True) |
| `spray-refused` | a correct password from a spraying source is refused | PASS (observed True) |
| `other-source-unaffected` | a different source still logs in | PASS (observed True) |
- **Limit:** velocity is counted per source address; a botnet spreading one failure per address is not aggregated, which no per-source counter can do

### `credential_handling` — PASS

*does a credential leak into a response, a URL or a log?*

| Probe | Expected | Result |
|---|---|---|
| `password-not-echoed` | the response never contains the password | PASS (observed False) |
| `me-has-no-hash` | the profile carries no password hash | PASS (observed False) |
| `me-has-no-secret` | the profile carries no MFA secret | PASS (observed False) |
| `error-no-echo` | the error body does not repeat the attempted password | PASS (observed False) |
| `token-not-a-query-credential` | a token in the query string grants nothing | PASS (observed 401) |
| `logs-were-captured` | the capture is live, so absence means redaction | PASS (observed True) |
| `log-no-password` | a failed attempt's password never reaches the log | PASS (observed False) |
| `log-no-credential` | the account password never reaches the log | PASS (observed False) |
| `log-no-token` | no session token reaches the log | PASS (observed False) |

## What this does not prove

- Executed in-process with the ASGI app and a temporary SQLite database: no TLS, no reverse proxy, no external IdP and no cluster, so a property that depends on those is marked UNPROVEN rather than passed.
- One process, one database file: federation across replicas, and a session store outage, are not exercised.
- No timing measurement: PBKDF2 work factor is asserted from the stored hash, not benchmarked against an attacker's budget.

**The verdict this drill supports:** login, session integrity, the second factor (including single-use codes), expiry with a separate idle clock, revocation, the password policy with credential history, lockout with per-source velocity, and credential redaction in responses and logs are enforced by the server and each has been executed against. What is missing is the deployment half — TLS, an external IdP path with a real directory, and an external breach corpus — and those are named above rather than folded into a pass.

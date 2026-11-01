# Authentication — eight questions, answered by execution

`cryptoscan.authentication-qualification/1` · generated 2026-11-01T03:11:43.978270+00:00 · **3 pass · 5 partial · 0 fail** · 55 probes

Each row drives the real auth router, the real session manager and the real user store through the production session gate. A row is `PASS` only when every probe produced the status it was supposed to; `PARTIAL` means everything passed but a named property was not exercised; `FAIL` means a probe answered wrong.

| Question | Verdict | Probes |
|---|---|---|
| **does a correct credential mint a session, and a wrong one never?** | **PASS** | 6/6 |
| **does the session token mean what it claims, and nothing more?** | **PASS** | 8/8 |
| **does the second factor exist, and can the first factor alone bypass it?** | **PARTIAL** | 10/10 |
| **does a session end when it says it will?** | **PARTIAL** | 5/5 |
| **can a session be ended before it expires, and does the gate honour it?** | **PASS** | 7/7 |
| **is a weak password refused, and is what is stored unusable?** | **PARTIAL** | 8/8 |
| **does repeated failure lock the account, and does the lock survive a restart?** | **PARTIAL** | 6/6 |
| **does a credential leak into a response, a URL or a log?** | **PARTIAL** | 5/5 |

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

### `mfa` — PARTIAL

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
| `recovery-code` | a recovery code is accepted once | PASS (observed 200) |

- **Not proven:** no external authenticator (hardware key, IdP push) is exercised: TOTP is the only second factor measured here
- **Limit:** the challenge is validated by the same session key as the session; an attacker with the signing key can forge both

### `expiry` — PARTIAL

*does a session end when it says it will?*

| Probe | Expected | Result |
|---|---|---|
| `expired-session` | 401 once the session has expired | PASS (observed 401) |
| `live-session` | a session inside its window is accepted | PASS (observed 200) |
| `expiry-claim` | the token carries an expiry | PASS (observed True) |
| `expiry-horizon` | expiry is inside the configured window | PASS (observed True) |
| `mfa-challenge-purpose` | an MFA challenge is not a session | PASS (observed None) |

- **Not proven:** idle timeout and absolute session lifetime per role are not implemented separately: there is one TTL

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

### `password_policy` — PARTIAL

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

- **Not proven:** no breach-list or history check: a strong-but-breached password is accepted, and password reuse across changes is not compared

### `lockout` — PARTIAL

*does repeated failure lock the account, and does the lock survive a restart?*

| Probe | Expected | Result |
|---|---|---|
| `failures-refused` | every failed attempt is 401 | PASS (observed {401}) |
| `locked-with-right-password` | the correct password is refused while locked | PASS (observed 401) |
| `lock-message` | the refusal says the account is locked | PASS (observed True) |
| `lock-is-stored` | a fresh service object still refuses the account | PASS (observed True) |
| `lock-is-per-account` | a lock on one account does not lock the platform | PASS (observed 200) |
| `audited` | the failures are in the audit trail | PASS (observed True) |

- **Not proven:** the harness counts 8 failures from one client; distributed attempts across source addresses are not counted together because the lock is per account and per attempt, not per-source velocity

### `credential_handling` — PARTIAL

*does a credential leak into a response, a URL or a log?*

| Probe | Expected | Result |
|---|---|---|
| `password-not-echoed` | the response never contains the password | PASS (observed False) |
| `me-has-no-hash` | the profile carries no password hash | PASS (observed False) |
| `me-has-no-secret` | the profile carries no MFA secret | PASS (observed False) |
| `error-no-echo` | the error body does not repeat the attempted password | PASS (observed False) |
| `token-not-a-query-credential` | a token in the query string grants nothing | PASS (observed 401) |

- **Not proven:** log redaction is measured by guide 121's log probe, not here; this row only reads HTTP responses

## What this does not prove

- Executed in-process with the ASGI app and a temporary SQLite database: no TLS, no reverse proxy, no external IdP and no cluster, so a property that depends on those is marked UNPROVEN rather than passed.
- One process, one database file: federation across replicas, and a session store outage, are not exercised.
- No timing measurement: PBKDF2 work factor is asserted from the stored hash, not benchmarked against an attacker's budget.

**The verdict this drill supports:** login, session integrity, the second factor, expiry, revocation, the password policy and lockout are enforced by the server and each has been executed against. What is missing is the deployment half — TLS, an external IdP path with a real directory, password breach lists, and per-role session lifetimes — and those are named above rather than folded into a pass.

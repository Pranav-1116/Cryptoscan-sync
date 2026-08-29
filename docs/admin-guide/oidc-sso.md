# OIDC single sign-on (bring your own identity provider)

CryptoScan verifies IdP-issued tokens; it never stores IdP passwords. The IdP
owns the credential — and its MFA. SSO is **off until `OIDC_ISSUER` is set**.

## Configure

```bash
OIDC_ISSUER=https://sso.corp.example.com/realms/main
OIDC_CLIENT_ID=cryptoscan
OIDC_AUTO_PROVISION=true          # create local viewer accounts on first login
# air-gap / pinned keys (optional — skips network discovery entirely):
OIDC_JWKS_FILE=/etc/cryptoscan/jwks.json
# or an explicit JWKS endpoint:
# OIDC_JWKS_URL=https://sso.corp.example.com/realms/main/protocol/openid-connect/certs
```

Without `OIDC_JWKS_FILE`/`OIDC_JWKS_URL`, the JWKS location is discovered from
`<issuer>/.well-known/openid-configuration` (5 s timeout, 5 min cache).

## Log in

```bash
TOKEN=$(oidc-token)   # whatever your IdP CLI/printout gives you
curl -s -X POST $API/api/v1/auth/oidc -H 'Content-Type: application/json' \
     -d "{\"token\": \"$TOKEN\"}"
# -> {"token": "<cryptoscan session>", "username": "kim", "roles": ["viewer"], ...}
```

The returned session token works exactly like a password-login session
(`Authorization: Bearer …`). Federated logins are audited as `auth.oidc_login`.

## What is enforced

- **RS256 only**, `kid` must exist in the JWKS (rotation-aware; unknown `kid` is rejected)
- `iss` must equal `OIDC_ISSUER`; `aud` must contain `OIDC_CLIENT_ID`
- `exp`/`iat` checked with `OIDC_CLOCK_LEEWAY` (default 60 s)
- Signature verified with real RSA math — `cryptography` package when installed,
  otherwise the `openssl` CLI (same backends as report signing)
- Provisioned accounts get an unguessable password hash: password login is
  impossible for federated users; roles are assigned **locally** (admin
  promotes via `PATCH /auth/users`), no IdP role mapping is claimed

## Not claimed

SAML, ES256 tokens, IdP-initiated logout, automatic role mapping from IdP
groups. If you need those, they belong in an IdP-side proxy or a future change.

## Rejecting a user

Disable the local account (`is_active=false`) — verified tokens then get 403,
even though the IdP still vouches for them.

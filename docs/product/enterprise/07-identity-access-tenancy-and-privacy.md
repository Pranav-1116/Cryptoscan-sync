# Identity, access, tenancy, and privacy

## 1. Identity options

The repository documents local accounts, TOTP MFA, OIDC flows, API keys, and
additional enterprise identity paths where implemented. Select one primary
operator identity source and maintain a break-glass procedure.

| Identity path | Best use | Important boundary |
|---|---|---|
| Local account | Bootstrap, development, break-glass | Password lifecycle and MFA remain local responsibilities |
| TOTP MFA | Additional factor for local accounts | Enrollment, recovery, and revocation must be controlled |
| OIDC | Workforce SSO and federation | Issuer, audience, signature, time, and role assignment must be checked |
| SAML/LDAP/AD/SCIM | Enterprise directory integration where enabled | Directory presence must not silently grant privileged roles |
| API key | CI, scanner, or service integration | Scope, expiry, rotation, storage, and revocation are mandatory |

Use the [OIDC guide](../../admin-guide/oidc-sso.md) and current API reference
for exact configuration and route behavior. Do not promise an identity
feature just because a configuration variable exists.

## 2. Authentication versus authorization

Authentication answers who is calling. Authorization answers what that caller
may do to which data. A secure request path must apply both:

1. authenticate session, token, or API key;
2. resolve customer/tenant context;
3. verify active membership or machine binding;
4. apply role and permission checks;
5. enforce resource ownership and scope; and
6. audit sensitive mutation, export, or administrative actions.

Invalid identity, expired session, missing membership, foreign resource, and
insufficient permission should produce deliberate, documented outcomes. Avoid
using a broad fallback that turns a failed scope lookup into an unscoped query.

## 3. Roles and responsibilities

The product role catalogue includes administrative, CISO, security analyst,
developer, auditor, business owner, scanner, readonly, and supervisor-style
responsibilities where enabled. The exact role-to-route matrix is maintained
in the API security code and admin documentation.

Use least privilege:

- analysts investigate and assign, but do not automatically administer the
  platform;
- developers receive build and repository results, not every customer export;
- auditors and supervisors are read-only unless a written exception exists;
- scanners submit only the evidence or job operations required;
- administrators manage identity and configuration, not risk acceptance for a
  customer; and
- business owners approve system context and residual business risk.

## 4. Tenant and customer boundary

The supported commercial deployment must be read together with the current
backend audit and production readiness documents. If a shared SaaS mode is
enabled, every tenant-scoped read, write, queue payload, background task,
export, and artifact path must carry scope and be tested for absence of
cross-tenant data.

A robust scope model includes:

- explicit customer/tenant identifier;
- membership and role resolved from the current request;
- API key binding that cannot be overridden by a header;
- worker payload carrying scope because workers have no browser session;
- database query and ORM safeguards;
- object/artifact prefix isolation;
- suspension and deletion semantics; and
- cross-scope negative tests that assert 404/403 behavior as designed.

If a deployment is single-customer, document that boundary clearly instead of
calling it multi-tenant. Shared infrastructure is not proof of tenant
isolation.

## 5. Session, key, and credential lifecycle

For every credential type define:

- owner and purpose;
- creation authority;
- minimum scope;
- storage location;
- expiration;
- rotation method;
- use logging;
- emergency revocation;
- replacement test; and
- deletion or disablement.

Do not put tokens, private keys, cloud secrets, or source credentials in
questionnaire answers, logs, evidence packs, tickets, or screenshots.

## 6. Privacy controls

Before connecting a source, identify:

- controller and processor roles;
- categories of data subjects and data;
- prohibited or sensitive data;
- legal basis and customer instruction;
- regions and cross-border access;
- retention and deletion trigger;
- support and subprocessor access;
- rights-request path; and
- DPIA/transfer assessment requirement.

The privacy engine should classify and redact before evidence persistence. A
fingerprint can support correlation without preserving the secret value. Verify
this with tests and sample data; do not rely solely on a policy statement.

## 7. Audit and access review

Audit high-risk actions such as login, role change, API-key creation or
revocation, scan authorization, baseline approval, exception approval, export,
connector dispatch, and data deletion. Review access periodically and retain:

- who had access;
- what they could access;
- when access was granted or revoked;
- which privileged actions occurred;
- reviewer and decision; and
- unresolved exceptions.

A hash-chained log detects changes to the stored sequence. Durable compliance
also requires protected export, retention, monitoring, and independent review.

## 8. Break-glass procedure

A break-glass account or path must be:

1. kept disabled or tightly restricted by default;
2. activated by an authorized incident owner;
3. time-limited and monitored;
4. limited to the incident scope;
5. followed by credential rotation;
6. reviewed by security and the customer owner; and
7. recorded with reason, actions, and closure.

Do not use an emergency path to bypass customer authorization or contractual
scope.

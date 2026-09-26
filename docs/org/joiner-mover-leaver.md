# Joiner / Mover / Leaver (JML) Procedure

**Version:** 1.0 (template) · **Owner:** [ORG: HR + IT security]
· **Criteria:** TSC CC6.7 (access upon separation / change), CC6.1,
CC6.3

Every step carries an ID (`JML-J*`, `JML-M*`, `JML-L*`); the readiness
check verifies the full set is present. Where the platform enforces the
step (marked **enforced**), the procedure says so — the checklist exists
to catch what automation cannot.

## 1. Joiner

| Step | Action | Owner | Deadline |
|------|--------|-------|----------|
| JML-J1 | Background check completed and passed [ORG: vendor / standard] | HR | before offer acceptance |
| JML-J2 | NDA + acceptable-use acknowledgement signed (AUP §6) | HR | before first day |
| JML-J3 | Account created with **least-privilege role** (RBAC catalogue; no `superadmin`/`ciso` without written justification) | IT security | day 1 |
| JML-J4 | **Enforced:** MFA (TOTP) active — the platform requires it; federated tenants provision via SCIM (`/scim/v2/Users`) with the IdP enforcing MFA | self + IT security | before first login |
| JML-J5 | Training assigned: T-01/T-02 (+T-03) started | security lead | day 1, complete within [ORG: 30 days] |
| JML-J6 | Device + secret-store access issued (no production secrets in code, chat or docs) | IT security | day 1 |
| JML-J7 | Added to the training-completion register (Training program §3) | security lead | day 7 |

## 2. Mover (transfer / promotion)

| Step | Action | Owner | Deadline |
|------|--------|-------|----------|
| JML-M1 | Role review against the new duties (least privilege re-assessed; RBAC roles changed via SCIM PATCH or access manager) | IT security | within [ORG: 5] business days |
| JML-M2 | Removed from roles that no longer fit (old role rights do not accumulate) | IT security | same change as JML-M1 |
| JML-M3 | Training delta assigned (e.g. promotion into on-call → T-04) | security lead | within [ORG: 10] business days |
| JML-M4 | Change noted in the access-review minutes when it touches privileged roles | access manager | next review cycle |

## 3. Leaver (resignation / termination / contractor end)

| Step | Action | Owner | Deadline |
|------|--------|-------|----------|
| JML-L1 | **Enforced:** account deactivated — soft-delete; all sessions and API keys invalidated by the platform | IT security | same day |
| JML-L2 | SCIM DELETE for federated tenants (`/scim/v2/Users/{username}`) | IdP admin | same day |
| JML-L3 | API keys owned by or issued for the person revoked (key allowlist rotation) | IT security | same day |
| JML-L4 | **Verified:** account absent from the next access-review export's active signals (deactivated accounts must not appear) | access manager | next export |
| JML-L5 | Device return / wipe; secret-store access revoked | IT security | [ORG: 1 business day] |
| JML-L6 | Data return or destruction certificate filed; confidentiality obligations confirmed (NDA survives) | HR + legal | [ORG: 10 business days] |

## 4. Rules

1. Separation events are **time-critical**: JML-L1/L2/L3 are same-day
   because a leaked production session is a SEV-1 in waiting
   (Incident Response Policy §3).
2. Contractors get the same lifecycle as staff, plus the contract-end
   date is the trigger (no manual recall needed).
3. Every JML event is audit-logged (the platform logs lifecycle
   actions); the quarterly access review samples leavers against the
   deactivation log as a standing control test.

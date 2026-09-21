# Change Management Policy

**Version:** 1.0 (draft) · **Owner:** [ORG: Engineering Director]
· **Applies to:** all changes to code, configuration, infrastructure and
data of CryptoScan · **Next review:** [ORG: YYYY-MM-DD]
· **Criteria:** TSC CC8.1, CC8.2, CC8.4, CC9.2

## 1. Purpose

Ensure that changes to the production platform are authorised, tested,
reversible and — uniquely for this platform — **evidenced**: every
released version carries a signed, tamper-evident production-evidence
record proving that its gates actually passed.

## 2. Change categories

| Category | Examples | Lane |
|----------|----------|------|
| **Standard** | dependency bumps, copy fixes, docs | normal PR flow |
| **Normal** | new features, behaviour changes, migrations | normal PR flow + review matrix |
| **Emergency** | SEV-1/SEV-2 fixes | emergency lane, retroactive review within 5 business days |
| **Restricted** | RBAC matrix, evidence-chain format, HSM key policy, tenancy logic | requires [ORG: CISO] + [ORG: Engineering Director] approval, dual review, explicit evidence run |

## 3. Requirements

1. **Authorisation.** All changes land via pull request against
   `main`; no direct pushes to `main` ([ORG: enforce via branch
   protection rules — the CI workflows defining these are maintained in
   the repository]).
2. **Review.** At least one approving review; Restricted changes require
   the named approvers. AI-assisted authorship is allowed but the human
   reviewer owns the approval.
3. **Testing.** The full test suite for the affected service must pass.
   Security-relevant changes (auth, session, tenancy, evidence) must
   add or update the tests that prove the property, not just the
   behaviour.
4. **Database migrations.** Alembic migrations are forward-only in
   production; each migration ships with a rollback migration or a
   documented manual rollback procedure (`docs/runbooks/`).
5. **Release gate.** A release is cut only when `scripts/release_check.py`
   passes: version checks, SBOM present, and a **fresh signed
   production-evidence run** — smoke + load + guard + (when available)
   DR drill — appended to the tamper-evident chain with a
   `identity.release = v<version>` entry. A FAILED phase blocks the
   release; SKIPs (e.g. no docker host for the drill) do not but are
   recorded loudly. The JWS signature (HS256 over canonical JSON) makes
   the record non-repudiable: `--no-evidence` is a loud, logged escape
   hatch, not a silent bypass.
6. **Rollback.** Every release keeps the previous artifact available;
   rollback is a deployment action, not a code change. Evidence of a
   failed release is retained — a broken evidence run is itself an
   incident (Incident Response Policy §4).
7. **Configuration.** Production configuration changes follow the same
   lanes; secrets are managed in the HSM/secret store and never in
   configuration files or the repository.

## 4. Deployment

1. Deployments are made by [ORG: named release engineer / on-call SRE].
2. Post-deployment verification: the evidence guard re-runs against the
   live instance and the smoke endpoint is checked before the release is
   declared complete.
3. The release record in `docs/production-evidence.md` — timestamp,
   commit, evidence id, content hash, JWS signature — is the artifact an
   auditor requests when they ask "prove release X was safe".

## 5. Evidence for the SOC 2 window

The signed evidence chain is append-only and Merkle-verifiable. During
the Type II observation window it is re-verified end-to-end
(`scripts/production_evidence.py` verify mode); any break is a SEV-1.
The per-release entries give the auditor a change-level view: every
version in the window maps to gates that provably ran and passed.

## 6. Exceptions

Emergency-lane changes are retroactively reviewed and their evidence
record reconciled within 5 business days; un-reconciled emergency
changes are reported in the monthly ops review.

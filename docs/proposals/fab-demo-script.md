# FAB demo script — 45 minutes, honest by design

Companion to `fab-poc.md` (the proposal). Goal of the meeting: leave with an
agreed PoC scope sheet and a date. The demo runs on the PoC stack
(`deploy/poc/`); every number on screen is real API output.

## Before you leave the office (checklist)

- [ ] Stack up: `docker compose -f deploy/poc/docker-compose.poc.yml --env-file poc.env up -d --build`; `bash scripts/smoke_test.sh` all 200s.
- [ ] Estate seeded with THEIR world, not a fantasy: 2–3 of their known
      public endpoints (one good TLS, one legacy TLS if reachable), telecom
      registry if the private-network module is in the conversation.
- [ ] Auditor account created (you'll hand the pack export to them live).
- [ ] Printed: `fab-poc.md` (2 pages), `enterprise-readiness.md` (the gap
      matrix — lead with it if the room is technical).
- [ ] Laptop with `sha256sum` ready — the pack verification is the closer.

## Act 1 — Sign-in & identity (5 min)

Log in as a named analyst account. Point at the SSO button rendering because
the IdP is configured (or honestly absent because it isn't). One sentence:
"OIDC with PKCE, SAML, LDAP, SCIM — your directory stays authoritative; the
auditor role sees reports and exports, nothing else."

## Act 2 — Network truth (10 min)

Run a scan on the seeded estate. The verdict table shows exactly what their
perimeter looks like from the outside: TLS_OK, NO_TLS (critical), an
UNREACHABLE with its reason. Say the sentence that wins engineers: **"Where
we couldn't see, it says so — every gap is named, nothing is guessed."**
Open one finding: severity, reference (TS 33.210 / SP 800-52r2), evidence.

## Act 3 — Cloud keys (10 min)

`POST /inventory/cloud/collect` with `dry_run: true` against THEIR account
(if they brought read-only creds) or the demo account. First show a
misconfigured run failing with the REAL provider error — then fix it live.
The skip list is the differentiator: unknown key types named with reasons.
Then flip to the CBOM/roadmap view: Shor-exposed families bucketed to NIST
IR 8547 dates. Sentence: "Your KMS is part of your quantum exposure, and now
it's in the same inventory as your network."

## Act 4 — Telecom (5 min, only if in scope)

Roaming matrix: partners, protecting SEPP, `pqc_ready` true only where
hybrid ML-KEM was actually probed. "Unknown stays unknown — this column
cannot be gamed."

## Act 5 — Automation with a conscience (5 min)

One rule: REACHABILITY_LOST → NOC alert + ticket. Show
`/automation/connectors` status (names only — "credentials never leave the
process"), preview the exact ServiceNow/Jira/Sentinel payload, dispatch.
Approval-gated actions open a human gate: "fail-closed — the platform never
mutates your estate on its own."

## Act 6 — The evidence closer (10 min)

Hand the mouse to THEIR audit person. As the auditor account, export the
pack. On the laptop: `sha256sum -c` against the embedded `manifest.json` —
every hash verifies, in front of the room. Close: "This is what your
regulator gets. Unedited, hash-verified, produced by the same API you just
watched fail honestly when it lacked credentials."

Then the ask: agree the scope sheet (network ranges, cloud roles, telecom
in/out) and pick the two-week window. PoC fee credited against year one.

## Objection one-liners (true, short)

- **"Who else uses it?"** → "You'd be among the first — that's why the PoC
  is fixed-scope and the fee is credited. The gap matrix you're holding is
  our actual roadmap, published."
- **"Certifications?"** → "ISO/SOC 2 of the product: not yet, it's a
  post-PoC company track. Today you can audit the controls yourself — the
  source, the tests (871), and the hash-chained audit trail are in the box."
- **"Mainframe / RACF?"** → "Not built yet. It's in the matrix as a gap —
  named, not faked. If it's in your scope sheet, it becomes build work with
  your environment as the test bench."
- **"Vs. IBM/Keyfactor?"** → "They're platforms programs grow into. We're
  the two-week answer to 'what crypto do we actually run' — with evidence
  you can hand to a supervisor on day 15."

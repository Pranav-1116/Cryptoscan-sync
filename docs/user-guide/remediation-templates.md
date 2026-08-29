# Remediation Templates (W51–52)

CryptoScan turns every failing finding into a **fix suggestion** — not just "MD5 is bad",
but the before/after code for your language, how to test the change, the standards that
require it, and for complex migrations a multi-step guide.

The templates are **advisory**. CryptoScan never pushes branches or opens pull requests;
the fix-branch payload below is applied by you or your CI.

## What a template contains

Each of the engine's rules has a template in **Python, Java, JavaScript, and Go**:

| Part | What it gives you |
|---|---|
| `before` / `after` | Language-specific code snippets showing the weak pattern and the replacement |
| `testing` | A checklist to verify the change (not just "it compiles") |
| `references` | Real citations — FIPS 197/203/204, SP 800-131A, RFC 8439/8446, OWASP |
| `effort_hours`, `risk` | Sizing inputs for sprint planning (a range, not a promise) |
| `guide` | For complex migrations, a link to a multi-step guide |

### Covered rules (15 templates × 4 languages = 60 snippets)

`replace-md5`, `replace-sha1-signing`, `replace-rc4`, `replace-des`, `replace-3des`,
`replace-blowfish`, `fix-ecb-mode`, `fix-aes-key-size`, `plan-rsa-pqc`, `plan-ecc-pqc`,
`plan-dh-pqc`, `plan-dsa-pqc`, `upgrade-tls`, `rotate-static-iv`, and
`remove-hardcoded-key` (key material found in source — always **P0**, regardless of the
algorithm it feeds).

The catalog endpoint reports the honest counts:

```bash
curl -s $API/api/v1/remediation/templates -H "Authorization: Bearer $TOKEN"
# {"templates": [...], "template_count": 15, "snippet_count": 60,
#  "languages": ["go","java","javascript","python"],
#  "guides": ["kms-migration","pqc-hybrid","tls-upgrade"]}
```

If a rule ever ships without a snippet for your language, the API falls back to Python and
sets `"requested_language_unavailable": true` rather than guessing.

## Per-scan suggestions with rendered fixes

```bash
curl -s "$API/api/v1/remediation/scans/$SCAN_ID/suggestions?language=java" \
     -H "Authorization: Bearer $TOKEN"
```

Each suggestion carries the finding's evidence id, file:line, priority (P0–P3), effort
estimate, and a `fix` block rendered for the requested language. Findings that need a
human get `fix: null` with the `manual-review` rule — no fake guidance.

## Fix-branch payload

One finding → everything needed to cut a branch:

```bash
curl -s -X POST "$API/api/v1/remediation/fix-branch" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"evidence_id": "ev-...", "language": "go"}'
```

Response: `branch` name, `commit_message`, `changes` (file, line, before/after), a PR
title/body with the testing checklist, and the `git` commands to run. CryptoScan itself
performs **none** of these steps.

## Multi-step guides

Complex migrations are not one snippet. Three guides ship today, each step with a
**verification** criterion and standards references:

- **`kms-migration`** — hardcoded keys → KMS/secret manager: inventory, provision with
  rotation, fetch at boot (fail closed), migrate data, rotate-and-remove.
- **`pqc-hybrid`** — FIPS 203 ML-KEM / FIPS 204 ML-DSA adoption: inventory, parameter
  choice, hybrid-first handshakes, certificates & policy, classical retirement.
- **`tls-upgrade`** — raise the TLS floor: measure real clients, fix stragglers first,
  enforce TLS 1.2+, verify externally.

Together with migration tracking (`docs/user-guide/migration-tracking.md`), the guides map
onto projects, tasks, and milestones so progress is measurable, not aspirational.

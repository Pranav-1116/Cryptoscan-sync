# CI/CD Policy Gates

Block deployments and merges that introduce weak, hardcoded, or forbidden
cryptography. The gate is **deterministic** — the YAML policy engine is the
only source of pass/fail; the gate never invents verdicts.

## How it works

```
PR / pipeline ──> scan ──> POST /api/v1/ci/gate {scan_id, profile}
                             │
                             ├─ decision: PASS | WARN | FAIL   (exit code 0 / 1)
                             ├─ SARIF 2.1.0 for GitHub code scanning
                             ├─ PR-comment markdown
                             └─ recorded → blocked-deployments stats
```

## The CLI

`scripts/ci_gate.py` is **stdlib-only** — installable by curl, no pip:

```bash
curl -fsSL -O https://raw.githubusercontent.com/<org>/CryproScan/<pinned-ref>/scripts/ci_gate.py

python3 ci_gate.py --scan-id "$SCAN_ID" \
  --api "$CRYPTOSCAN_API" --token "$CRYPTOSCAN_TOKEN" \
  --profile strict \
  --sarif cryptoscan.sarif.json \
  --format pr-comment > pr-comment.md
```

Exit codes: `0` PASS/WARN (merge allowed), `1` FAIL (blocked), `2`
configuration error. `--format json` (default) prints the full machine
result; `--format pr-comment` renders markdown ready to post.

## Policy profiles

One gate, three enforcement postures (`--profile`, default `standard`):

| Profile | Blocks on | Use when |
|---|---|---|
| `standard` | weak crypto in blocking purposes, hardcoded keys, blocking drift | default CI |
| `strict` | everything `standard` does **plus every warning** (any non-PASS fails) | regulated / payment paths |
| `lenient` | only hardcoded keys and cryptographic downgrades | legacy repos on a ramp-up |

Profiles never change what is *found* — only what *blocks*. The response
carries the profile name and both lists regardless of posture.

## Integrations (ready-made)

| System | Artifact |
|---|---|
| GitHub Actions | `integrations/github/action.yml` (composite action; comment as step output) |
| Jenkins | `integrations/jenkins/Jenkinsfile` (declarative stage + SARIF archiving) |
| GitLab CI | `integrations/gitlab/cryptoscan-gate.yml` (job + SAST report) |
| ArgoCD | `integrations/argocd/pre-sync-hook.yaml` (PreSync Job — a FAIL halts the sync) |

## Blocked-deployments tracking

Every `POST /ci/gate` call is recorded (fail-open: a logging problem never
breaks CI) with decision, profile, blocking counts, repo, and actor. Roll
it up for the dashboard:

```
GET /api/v1/ci/gate-evaluations?days=30
→ { evaluations, blocked, passed, warned, blocking_findings,
    by_repo: [{repo, blocked, findings}...], profiles: {...} }
```

## Posting the PR comment

With the composite action the markdown arrives as the `comment` output;
post it with [github-script](https://github.com/actions/github-script):

```yaml
- uses: actions/github-script@v7
  if: always()
  with:
    script: |
      const body = `${{ steps.gate.outputs.comment }}`;
      await github.rest.issues.createComment({
        ...context.repo, issue_number: context.issue.number, body
      });
```

## Notifications

Gate failures flow through the existing alert channels — email (SMTP) and
the signed webhook alerter (Slack/Teams/Jira-compatible; see
`docs/admin-guide/` and `services/drift/drift/alerts/webhook_alerter.py`).

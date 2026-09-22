# SBOM supply-chain gate

Decide whether a build's **dependency set** is safe to ship, and prove it
later. The gate is deterministic and offline: the policy object is the only
source of pass/fail, advisory matching is version-range arithmetic against a
feed you supply, and a component above an advisory's fixed version is not
reported as affected.

Two entry points, one engine:

| | When to use |
|---|---|
| `POST /api/v1/devsecops/sbom/{artifact_id}/gate` | reviewing a stored artifact in the console / an approval workflow |
| `python -m devsecops.sbom_gate` | blocking a pipeline between build and deploy |

## The CLI

No third-party imports — argparse, json and the policy engine only, so it runs
in an air-gapped runner with nothing installed. Add the service directory to
`PYTHONPATH` (or run from a checkout that already exports it):

```bash
export PYTHONPATH="$PWD/services/devsecops:$PYTHONPATH"
python -m devsecops.sbom_gate sbom.cdx.json --policy gate.json

# or straight from a stored artifact, no local copy needed
curl -fsS -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/devsecops/sbom/$ARTIFACT_ID/download" \
  | python -m devsecops.sbom_gate - --require-minimum-elements --max-unpinned 5
```

Exit codes are stable and safe to branch on:

| Code | Meaning |
|---|---|
| `0` | passed — every blocker rule satisfied |
| `1` | **blocked** — a policy threshold was crossed |
| `2` | usage or IO error (bad flag, unreadable file, bad policy file) |
| `3` | the document is not parseable CycloneDX/SPDX JSON |

Warnings never change the exit code; they are advisory by design. `--json`
prints the whole evaluation (effective policy, counts, blockers, warnings) so
the pipeline archives evidence rather than a log line.

## Policies

The policy keys and their defaults (`DEFAULT_GATE_POLICY`):

```json
{
  "allow_critical": 0,
  "allow_high": null,
  "deny_licenses": ["GPL-3.0-only", "AGPL-3.0-only"],
  "require_minimum_elements": false,
  "max_unpinned": null,
  "require_signed": false
}
```

* `allow_high: null` means "no limit, but warn" — a high advisory blocks only
  when you set a number.
* `deny_licenses` matches the component's **declared** license (npm/PyPI
  metadata or a lockfile's `license` field). An undeclared license is never
  treated as denied, and never treated as permitted either — it simply is not
  evidence.
* `require_minimum_elements` turns the NTIA gaps from a warning into a blocker.
* `require_signed` only blocks when the caller *asserts* the artifact is
  unsigned (`--unsigned`); the document alone cannot prove signing.

Blocker codes name the rule that fired: `GATE-CVE-CRITICAL`, `GATE-CVE-HIGH`,
`GATE-LICENSE-DENIED`, `GATE-UNPINNED`, `GATE-UNSIGNED`,
`GATE-MINIMUM-ELEMENTS`.

## CI example

```yaml
- name: SBOM + gate
  env:
    PYTHONPATH: services/devsecops
  run: |
    python -m devsecops.sbom_gate sbom.cdx.json \
      --policy ci/gate.json \
      --unpinned "$UNPINNED_COUNT" \
      --json > sbom-gate.json
```

The step fails the job on exit code 1, and `sbom-gate.json` becomes the
evidence record attached to the build.

## Generating the SBOM and the advisories

```bash
curl -fsS -X POST "$API/api/v1/devsecops/sbom/scan" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"source","target":"/srv/build/app","format":"cyclonedx",
       "feed":'"$(cat advisories.json)"'}' > scan.json
```

* Lockfiles are merged by default (`"use_lockfiles": false` reproduces the
  declared-only view) so the transitive tree is in the document — a
  manifest-only SBOM under-reports and is the usual reason a supplier SBOM
  gets rejected.
* `feed` is an NVD-style advisory array
  (`{"cve_id", "severity", "affected":[{"ecosystem","package","ranges":[{"fixed"}]}]}`).
  Ecosystems are mapped from the package manager (`pip → pypi`, `go → golang`,
  `gradle → maven`, `bundler → gem`, …).
* **Nothing is checked unless a feed is supplied.** The manifest therefore
  records `feed_supplied` next to `vulnerability_count`: zero advisories because
  no feed was applied reads differently from zero advisories found, and the
  platform never blurs the two.

## Re-scan control: "did anything change under me?"

Artifacts record the options that produced them, so the same scan can be
repeated and compared in one call:

```bash
curl -fsS -X POST "$API/api/v1/devsecops/sbom/$ARTIFACT_ID/rescan" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"policy":{"allow_critical":0}}'
```

The response contains the fresh artifact id, an SBOM-to-SBOM `diff`
(added/removed, upgrade/downgrade with direction, license changes,
crypto-relevant deltas and an `UNCHANGED`/`UPDATED`/`CRYPTO_REVIEW` verdict) and
the `gate` verdict for the new document. A version bump that pulls in a crypto
library reads as `CRYPTO_REVIEW`, not as a quiet update.

Advisory feeds are not persisted (they can be large and are supplied per scan),
so re-scanning a fed artifact runs without one and says so in `notes`, naming the
advisories the previous artifact recorded. That matters when a revert is the
change: rolling `jws` back to a version an earlier feed flagged still shows as a
`downgrade` in the diff, and the note tells you the fresh gate verdict is
unchecked rather than clean — re-run the scan with a feed before trusting it.

## Provenance

Everything the gate reads is verifiable after the fact: the artifact stores the
exact BOM bytes, their sha256, and an HMAC-SHA256 manifest signature
(`GET /sbom/{id}/verify` re-checks both and names the check that failed).
`GET /sbom/{id}/report?fmt=markdown` renders the auditor summary — crypto
inventory, pinning, minimum-elements table, provenance — and
`DELETE /sbom/artifacts?older_than_days=N` applies retention.

Read-only (`readonly`/`viewer`) accounts may list, download, verify, report,
diff, validate and gate; scanning, re-scanning and pruning require an operator
role.

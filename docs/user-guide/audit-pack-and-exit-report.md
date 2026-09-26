# Audit pack, exit report, engagement archive

Three auditor-gated deliverables close the loop from scanning to hand-over
(`GET /api/v1/audit-export/…`, role `auditor`+). All three are
hash-sealed: the client's audit function verifies them with any
`sha256sum -c`-style check — no trust in the exporter required. UI:
**Reports** page.

| Deliverable | Endpoint | What it is |
|---|---|---|
| **Audit pack** | `GET /audit-export/pack` | Examiner ZIP of the whole estate — certificates (incl. ACM rows), payment keys, cloud KMS, code findings, telecom snapshot — with a `manifest.json` of SHA-256s over every file |
| **Exit report** | `GET /audit-export/exit-report` | The PoC verdict as data: estate counts, per-estate coverage, success-criteria scorecard, limitations, roadmap families. `format=json` or `format=md` (markdown + `X-Report-Hash` header) |
| **Engagement archive** | `GET /audit-export/engagement-archive` | The final hand-over in ONE zip: the audit pack + the exit report in both renderings + a top-level manifest covering every file |

## The exit report scorecard (SC-1…SC-4)

The report scores the agreed PoC success criteria **from collected data,
never from assertions**:

- **SC-1 — coverage ≥ 90%** evaluated from the computed worst estate.
  Coverage = collected vs. skipped, where every skip carries its verbatim
  reason. An estate with nothing measured renders **NOT MEASURABLE** —
  never a faked 100%.
- **SC-2 — CBOM + roadmap accepted** — met by inventory + flagged
  Shor-exposed families (vacuous-clean estates allowed and labeled);
  *formal* acceptance is SC-4.
- **SC-3 — pack verifies end-to-end** — the pack's SHA-256 manifest;
  verification is literally a checksum run.
- **SC-4 — client acceptance** — met **only** when a human name is passed
  as `accepted_by`. The report never infers sign-off: no name → NOT MET,
  "pending".

## Determinism and verification

Identical estate + scope ⇒ identical report. The `report_hash` is a
SHA-256 over the canonical JSON (excluding the hash itself);
`verify_exit_report(report)` recomputes it — any later edit of the JSON
breaks verification loudly. The markdown rendering is deterministic too,
and `exit-report.json` + `exit-report.md` in an engagement archive are the
**same report** (same hash in both).

```bash
# generate + verify the final archive
curl -s -o archive.zip "$API/api/v1/audit-export/engagement-archive?client=Acme&window=2026-09-14..25" -H "Authorization: Bearer $T"
python3 - <<'PY'
import json, zipfile
from reporting.exit_report import verify_exit_report
z = zipfile.ZipFile("archive.zip")
m = json.loads(z.read("manifest.json"))
assert all(len(entry["sha256"]) == 64 for entry in m["files"].values())
assert verify_exit_report(json.loads(z.read("exit-report.json"))) is True
print("verified:", m["client"], m["exit_report_hash"][:16])
PY
```

## Honest-empty guarantees

- Registered-but-empty telecom pass → honest zeros in the report.
- Never-scanned telecom → the telecom block is **absent**, not zeroed.
- Skipped cloud/ACM items appear verbatim under *limitations* with their
  collector reason.
- Every count comes from the same queries as the audit pack — the report
  cannot disagree with the evidence it ships with.

Scope and commercial framing: [proposals/fab-poc.md](../proposals/fab-poc.md).
Bring-up: [deploy/poc/CHECKLIST.md](../../deploy/poc/CHECKLIST.md).

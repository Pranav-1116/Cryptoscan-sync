# Retained execution records — original45 follow-up

**2026-10-24 UTC; baseline731fbbcb2b1d200fd7cb13ecd61176688ea218ba.**
See the [execution report](../bank-original45-2026-10-24.md) for what changed,
compatibility and unperformed acceptance. The containing publication and the
[source/record manifest](../bank-original45-results-2026-10-24.json) bind final
source and retained records. Earlier reports are historical, not rewritten.

## Records

- `initial-red.log`:34failed/1passed new native-output/denominator cases.
- `api-red.log`:8failed/1passed before API adapter wiring; the response-shape
  assertion was corrected to match the existing API before retaining this run.
- `shared-context-red.log`:1failed/26passed before shared-asset merge.
- `api-context-red.log`:2failed/11passed before persisted context/system-reference fixes.
- `cli-red.log`:3failed/10passed before null-safe consistent CLI output.
- `ui-red.log`:3 failing existing Accuracy-page contracts before fixes.
- `parameters-red.log`:26failed/29passed for byte units, full SLH names and native
  parameter IDs. `parameters-green.log`:129passed including existing registry cases.
- `plan-prose-red.log`:2failed/15passed before planning prose fixes.
- `summary-compatibility-failure.log`:1failed/901passed from the retained old
  summary string expectation; the numeric cohort contract was not weakened.
- `intermediate-902.log` / `intermediate-902.xml`:902passing cases before adding
  the last schema-invalid API metadata cases.
- `invalid-metadata-red.log`:3failed/13passed before the invalid-name parsing guard.
- `regression.log` / `regression.xml`:**905passed,4warnings**, no failures/errors/skips.
- `ui-focused-green.log`:17passing Accuracy/CBOM page tests, no new act/navigation warnings.
- `frontend.log` / `frontend.xml`:**552passed/53files**, no failures/errors/skips;
  20 existing React act warnings in CriticalScope/Tenancy remain disclosed.
- `typecheck.log` / `build.log`:successful current frontend toolchain checks.
- `register-review.json`:57mapped, integrity PASS, all acceptance requirements open.
- `strict-review.json`:expected strict exit1 (blocked), not invalid-data exit2.

Red records are incremental implementation states, not all the clean baseline
commit. They are not a distinct-defect count. Retained text removes ANSI and
trailing whitespace only. Inputs/identities/canaries are synthetic; no real
private keys, customer data or installed dependencies are committed.

## Environment and reproduction

Python3.11 virtualenv installed using root `requirements.txt` constrained by
`requirements.lock.txt`, including jsonschema4.25.1 and five newly pinned
packages in total. pytest9.1.1, FastAPI0.141.1, SQLAlchemy2.0.52,
Pydantic2.13.5. `pip check` passed. API persistence/session tests use disposable
SQLite, not PostgreSQL qualification. Node22.22.3/npm10.9.8; frontend lockfile
installed with `npm ci --ignore-scripts`. No workflow was changed.

From repository root in an approved constrained environment, use **external**
output paths, not retained files:

```bash
bash docs/readiness-evidence/bank-original45-2026-10-24/run-python-tests.sh --junitxml=/external/python.xml
npm --prefix frontend run typecheck
npm --prefix frontend run build
npm --prefix frontend test -- --reporter=default
python docs/readiness-evidence/bank-original45-2026-10-24/reproduce-sample.py /external/synthetic-output
python scripts/bank_vendor_questionnaire.py
if python scripts/bank_vendor_questionnaire.py --strict; then
  echo 'Unexpected qualification: investigate' >&2
  exit 1
else
  result=$?
  test "$result" -eq 1
fi
```

The sample runner is pure metadata generation/planning over the committed eight
inputs; no scanner, DB, network, HSM or cryptographic operation is invoked.
Its fixed fixture timestamp is not a claimed observation time. Both generated
JSON outputs were regenerated and byte-compared successfully before publication.

Neither test count, schema validity, an internally produced signature nor a
source hash establishes bank acceptance, complete discovery, current regulator
approval, a qualified native PQC implementation or a staffed SLA.

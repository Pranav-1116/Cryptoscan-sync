# Scanner qualification and readiness projection

This repository now has two additional truth-preserving tools:

- `scripts/scanner_qualification_matrix.py` invokes the real scanner CLIs for
  operator-supplied staging inputs. A family without an input is recorded as
  `UNCONFIGURED`; a dependency or credential problem remains `UNAVAILABLE`,
  `BLOCKED`, `PREFLIGHT`, or `FAIL` as emitted by the adapter.
- `scripts/realtime_replica_drill.py` exercises the production event bus and
  Redis federation adapter against an in-process protocol double. Its scope is
  explicitly a transport simulation; it is not Redis HA, load, multi-host, or
  customer evidence.

The API endpoint `GET /api/v1/readiness/summary` exposes the same readiness
contract for the active tenant. It keeps these boundaries explicit:

1. a scanner result is not a customer/provider qualification;
2. a complete local scanner matrix is not an independent security review;
3. an event-transport simulation is not a multi-replica deployment drill;
4. absent external evidence stays `SKIP` and regulated production stays
   `BLOCKED`.

## Staging run

```bash
python scripts/scanner_qualification_matrix.py \
  --source /authorized/staging/source \
  --universal /authorized/staging/source \
  --network staging.example:443 \
  --container /authorized/staging/image.tar \
  --ot /authorized/staging/ot-captures \
  --telecom /secure/staging/telecom-registry.json \
  --payment /secure/staging/payment-audit.json \
  --keyassure /secure/staging/keyassure.json \
  --binary /authorized/staging/firmware.bin \
  --devsecops /authorized/staging/sbom.json \
  --out /secure/evidence/scanner-matrix
```

Only use `--strict` after every required family has a real staging input and
the operator has reviewed the output. The aggregate is `INCOMPLETE` when any
family is `UNCONFIGURED`, `SKIP`, or `PREFLIGHT`; it is never collapsed into
`PASS`. The report contains content hashes and metadata references, not key or
secret values.

## Dependency and cascade coverage

Static cascade output now includes `package_dependencies` from manifests and
lockfiles, with direct/transitive classification, ecosystem, version, parent
relationship, evidence type/reference, observation time, confidence, and
unresolved relationship records. The existing source import/call graph,
shared key references, business-system map, weak parameters, and migration
waves remain separate evidence sections. Bounded worker/API projections expose
truncation and unresolved counts instead of silently dropping relationships.

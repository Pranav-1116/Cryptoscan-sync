"""Opt-in matched native-SQL/API workload, not a deployment capacity claim."""
import json
import hashlib
import os
import subprocess
import time
import types
from pathlib import Path
import pytest
from sqlalchemy import event, text
from db.models.system import System
from db.models.evidence_record import EvidenceRecord
from api.assurance import relationships, store
# These fixtures are also imported by test_isolated_cohort_recovery during collection.
from test_workflow_postgres import quality_cluster as quality_cluster, pgdb as pgdb, banks as pg_banks  # noqa: F401
from test_assurance_workflows import assured as assured, P, done, new_scan
from test_software_supply_chain_api import register, attach, deploy
from test_package_identity_integrity import stored, relationship

pytestmark = pytest.mark.live
BASELINE = "c48f667e3dee70b0ffc48f338004382b6543f94f"


@pytest.fixture
def banks(pg_banks, monkeypatch):  # noqa: F811 — exported cohort fixture wraps the imported base
    clients, db, tmp = pg_banks
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp / "sboms"))
    import api.routers.devsecops as ds
    monkeypatch.setattr(ds, "_SBOM_STORE", None)
    db.add(System(id="system-a", name="synthetic-perf", environment="prod", tenant_id="a")); db.commit()
    yield clients, db, tmp


def test_matched_trace_api_workload(assured, monkeypatch):
    clients, db, _ = assured
    client = clients["bank_a"]
    components = [{"name": f"crypto-{n}", "version": "1.2.3", "purl": f"pkg:maven/org.bank/crypto-{n}@1.2.3", "bom-ref": f"component-{n}"} for n in range(50)]
    binding = attach(client, register(client), stored(client, {"bomFormat": "CycloneDX", "components": components}))
    done(deploy(client, {"id": binding["artifact_id"]}, system_id="system-a"))
    scan = new_scan(db)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=scan.id).one()
    for n, component in enumerate(components):
        value = relationship(binding, component["purl"], evidence); value.pop("expected_revision")
        identifier = store.subject("synthetic-perf", str(n))
        first = store.append(db, "a", "bom_relationship", identifier, 0, {**value, "state": "PROPOSED", "trust": "DECLARED_NOT_VERIFIED"}, "fixture-author")
        store.append(db, "a", "bom_relationship", identifier, 1, {**first.payload, "state": "REVIEWED", "trust": "CUSTOMER_REVIEWED_ASSERTION_NOT_INDEPENDENT_RUNTIME_PROOF"}, "fixture-reviewer")
    # Exact published baseline; both functions see the SAME SQL/blobs/identities.
    original = types.ModuleType("api.assurance.trace_baseline"); original.__package__ = "api.assurance"
    code = subprocess.check_output(["git", "show", BASELINE + ":services/api/api/assurance/relationships.py"])
    exec(compile(code, "published_trace_baseline", "exec"), original.__dict__)
    candidate = relationships.trace
    output, reference, statements = {}, None, []
    def observed(_connection, _cursor, statement, *_args): statements.append(statement)
    event.listen(db.get_bind(), "before_cursor_execute", observed)
    try:
        for name, fn in [("before", original.trace), ("after", candidate)]:
            monkeypatch.setattr(relationships, "trace", fn)
            for _ in range(3): done(client.get(P + "/applications/system-a/trace"), 200)
            samples, queries = [], []
            for _ in range(25):
                statements.clear(); start = time.perf_counter()
                response = client.get(P + "/applications/system-a/trace")
                samples.append((time.perf_counter() - start) * 1000)
                body = done(response, 200); queries.append(len(statements))
                if reference is None: reference = body
                assert body == reference and len(body["paths"]) == 50
                assert body["runtime_verified"] is body["complete"] is False
            ordered = sorted(samples)
            output[name] = {"samples_ms": samples, "p50_ms": ordered[12], "p95_ms": ordered[23], "p99_ms": ordered[24],
                            "query_counts": queries, "response_bytes": len(response.content)}
    finally:
        event.remove(db.get_bind(), "before_cursor_execute", observed)
        monkeypatch.setattr(relationships, "trace", candidate)
    with db.get_bind().connect() as connection:
        plan = connection.execute(text("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM evidence_records WHERE tenant_id='a' AND id=:id"), {"id": evidence.id}).scalar()
    output.update(baseline_commit=BASELINE, components=50, reviewed_edges=50, concurrency=1, warmups=3, repetitions=25,
        correctness_exact_output_unchanged=True, query_plan=plan,
        implementation_sha256=hashlib.sha256(Path(relationships.__file__).read_bytes()).hexdigest(),
        targets_approved="No correctness regression; p95/p99 not slower; chosen bottleneck improvement >=20%")
    target = os.getenv("CRYPTOSCAN_MEASURE_OUT")
    assert target, "Set an external result path for opt-in measurement"
    Path(target).write_text(json.dumps(output, indent=2, default=str) + "\n")
    if os.getenv("CRYPTOSCAN_REQUIRE_IMPROVEMENT") == "1":
        assert output["after"]["p95_ms"] <= .8 * output["before"]["p95_ms"]
        assert output["after"]["p99_ms"] <= output["before"]["p99_ms"]

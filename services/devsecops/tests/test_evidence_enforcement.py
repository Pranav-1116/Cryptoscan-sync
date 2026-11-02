"""The evidence rules as guards on the paths that actually run.

Guide 133 added the rules; this module pins the places they are *enforced*:
the source scanner's graph budget, the artifact store's refusal to degrade to
temporary storage in production, the manifest's record of where evidence went,
and the document-level vulnerability/twin/history answers a report needs.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from devsecops import artifact_store as store
from devsecops import sbom_evidence as se
from devsecops import sbom_scan

AS_OF = date(2026, 11, 2)
DIGEST = "sha256:" + "a" * 64


def _artifact(digest: str = DIGEST) -> se.ArtifactIdentity:
    return se.ArtifactIdentity("ghcr.io/bank/payments-api", digest)


def _observation(*, digest: str = DIGEST) -> se.DeploymentObservation:
    return se.DeploymentObservation(
        "payments-api-prod", "PRODUCTION",
        se.ArtifactIdentity("ghcr.io/bank/payments-api", digest),
        "payments-api-7d9c4f-x2b6q", AS_OF, "OBS-1102-01", "k8s")


def _sbom(components: tuple[dict, ...] = ({"name": "openssl", "version": "3.0.13",
                                          "crypto_relevant": True},),
          sbom_id: str = "SBOM-1", created_at: date = AS_OF) -> se.SbomRecord:
    return se.SbomRecord(sbom_id, _artifact(), components, created_at=created_at,
                         build_id="BUILD-1")


def _chain_lockfile(depth: int) -> str:
    packages: dict[str, dict] = {"": {"dependencies": {"p0": "^1.0.0"}}}
    for index in range(depth):
        row: dict = {"version": "1.0.0"}
        if index + 1 < depth:
            row["dependencies"] = {f"p{index + 1}": "^1.0.0"}
        packages[f"node_modules/p{index}"] = row
    return json.dumps({"lockfileVersion": 3, "packages": packages})


# ------------------------------------------------------------ graph budget -- #


def test_an_ordinary_tree_is_within_budget(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"jose": "^5.0.0"}}),
                                          encoding="utf-8")
    result = sbom_scan.scan_source(str(tmp_path))
    assert result["parser_budget"]["verdict"] == "WITHIN_BUDGET"
    assert result["parser_budget"]["action"] == "NONE"
    assert result["packages"]


def test_a_deep_graph_withholds_the_edges_and_keeps_the_inventory(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(_chain_lockfile(80), encoding="utf-8")
    result = sbom_scan.scan_source(str(tmp_path))
    budget = result["parser_budget"]
    assert budget["verdict"] == "REFUSED"
    assert budget["action"] == "EDGES_WITHHELD"
    assert budget["edges_withheld"] > 0
    assert any("depth" in problem for problem in budget["problems"])
    assert result["dependencies"] == []
    # the components are still the answer to "what is in here"
    assert len(result["packages"]) == 80


def test_a_cyclic_lockfile_breaks_the_back_edges_rather_than_recursing(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "^1"}},
        }}), encoding="utf-8")
    result = sbom_scan.scan_source(str(tmp_path))
    budget = result["parser_budget"]
    assert budget["verdict"] == "REFUSED"
    assert budget["action"] == "CYCLES_BROKEN"
    assert budget["edges_broken"] == 1
    assert len(result["dependencies"]) == 1  # a -> b survives; the back edge does not


def test_a_component_limit_is_enforced_from_the_caller(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"jose": "^5.0.0"}}),
                                          encoding="utf-8")
    result = sbom_scan.scan_source(
        str(tmp_path), budget=se.ParserBudget(max_components=0))
    assert result["parser_budget"]["verdict"] == "REFUSED"
    assert result["parser_budget"]["action"] == "EDGES_WITHHELD"


# ---------------------------------------------------------------- storage -- #


@pytest.fixture()
def clean_env(monkeypatch, tmp_path):
    for name in ("SBOM_STORAGE_DIR", "SBOM_STORAGE_BACKUP_DIR", "SBOM_RETENTION_DAYS",
                 "ENVIRONMENT", "CRYPTOSCAN_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    return tmp_path


def test_development_may_use_the_store_it_configured(clean_env, monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    status = store.storage_status()
    assert status["verdict"] == "ALLOW"
    assert status["mode"] == "CONFIGURED"
    assert status["integrity_verified"] is True  # a real write/read round-trip


def test_production_without_a_store_is_refused_not_fallen_back(clean_env, monkeypatch) -> None:
    monkeypatch.delenv("SBOM_STORAGE_DIR")
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(store.StorageRefused, match="no artifact store is configured"):
        store.artifact_storage()
    assert store.storage_status()["mode"] == "NO_STORE"


def test_production_without_backup_or_retention_is_refused(clean_env, monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(store.StorageRefused) as excinfo:
        store.artifact_storage()
    message = str(excinfo.value)
    assert "no backup target" in message
    assert "no retention period" in message


def test_a_fully_configured_production_store_is_used(clean_env, monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SBOM_STORAGE_BACKUP_DIR", str(clean_env / "dr"))
    monkeypatch.setenv("SBOM_RETENTION_DAYS", "2555")
    status = store.storage_status()
    assert status["verdict"] == "ALLOW"
    assert status["backup"] is True
    assert status["retention_days"] == 2555
    assert isinstance(store.artifact_storage(), object)


def test_the_store_refuses_to_claim_integrity_it_did_not_verify(tmp_path, monkeypatch) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(blocker / "sboms"))
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SBOM_STORAGE_BACKUP_DIR", str(tmp_path / "dr"))
    monkeypatch.setenv("SBOM_RETENTION_DAYS", "365")
    status = store.storage_status()
    assert status["writable"] is False
    assert status["integrity_verified"] is False
    assert status["verdict"] == "REFUSE"
    with pytest.raises(store.StorageRefused):
        store.artifact_storage()


def test_the_manifest_records_where_the_artifact_was_written(clean_env, monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "test")
    bom = sbom_scan.render_sbom({"target": "/srv/app",
                                 "packages": [{"name": "openssl", "version": "3.0.13"}],
                                 "libraries": [], "binaries": [], "vulnerabilities": [],
                                 "manifests": [], "lockfiles": [], "dependencies": []},
                                fmt="cyclonedx", created_by="tester")
    stored = store.store_binary_artifact(
        scan={"target": "/srv/app", "files_walked": 1},
        result={"target": "/srv/app", "packages": [{"name": "openssl", "version": "3.0.13"}],
                "manifests": [], "lockfiles": [], "dependencies": [], "libraries": [],
                "binaries": []},
        bom=bom, cbom={}, created_by="tester")
    recorded = stored["manifest"]["storage"]
    assert recorded["environment"] == "test"
    assert recorded["integrity_verified"] is True
    assert recorded["root"].endswith("sboms")
    assert Path(recorded["root"]).is_dir()


# ------------------------------------------------ vulnerability at scale -- #

FEED = {"name": "osv", "version": "2026-11-01", "updated_at": date(2026, 11, 1)}
ADVISORY = [{"id": "CVE-2024-6119", "package": "pkg:generic/openssl",
             "affected_versions": ["3.0.11"]}]


def test_a_document_reports_what_was_assessed_and_what_was_not() -> None:
    sbom = _sbom((
        {"name": "openssl", "version": "3.0.11", "purl": "pkg:generic/openssl@3.0.11"},
        {"name": "curl", "version": "8.4.0", "purl": "pkg:generic/curl@8.4.0"},
        {"name": "mystery-lib", "version": None, "purl": None},
    ))
    report = se.assess_document(sbom, feed=FEED, advisories=ADVISORY, as_of=AS_OF)
    assert report["counts"]["MATCHED"] == 1
    assert report["counts"]["ASSESSED_NO_MATCH"] == 1
    assert report["counts"]["INSUFFICIENT_IDENTIFIER"] == 1
    assert report["assessed"] == 2 and report["unassessed"] == 1
    assert "may not be reported as clean" in report["statement"]
    assert set(se.VULN_ROW_FIELDS) <= set(report["components"][0])


def test_a_stale_feed_makes_every_component_unassessed() -> None:
    stale = {"name": "osv", "version": "2026-08-01", "updated_at": date(2026, 8, 1)}
    report = se.assess_document(_sbom(), feed=stale, advisories=ADVISORY, as_of=AS_OF)
    assert report["counts"]["STALE_FEED"] == 1
    assert report["assessed"] == 0
    assert "not assessed" in report["statement"]


def test_no_feed_at_all_is_not_assessed_and_says_so() -> None:
    report = se.assess_document(_sbom(), feed=None, as_of=AS_OF)
    assert report["counts"]["NOT_ASSESSED"] == 1
    assert report["unassessed"] == 1


# ------------------------------------------------------------- twin edges -- #


def test_an_observed_artifact_reaches_a_running_workload() -> None:
    build = se.BuildIdentity("9f2c1ab4d7", "BUILD-1", "github-actions", "release",
                             _artifact(), "SBOM-1", started_at=AS_OF, finished_at=AS_OF)
    graph = se.twin_edges(_sbom(), build=build, deployments=[_observation()],
                          application="payments-api", business_system="Card Processing",
                          algorithms={"openssl": ["AES-256-GCM"]})
    kinds = {edge["kind"] for edge in graph["edges"]}
    assert {"CONTAINS", "DESCRIBED_BY", "PRODUCED", "DEPLOYED_AS", "RUNS_AS", "SERVES",
            "HAS_CAPABILITY"} <= kinds
    for edge in graph["edges"]:
        assert edge["evidence_id"] and edge["evidence_type"] and edge["source"]
        assert edge["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    deployment = next(edge for edge in graph["edges"] if edge["kind"] == "DEPLOYED_AS")
    assert deployment["evidence_id"] == "OBS-1102-01"
    assert deployment["evidence_type"] == "OBSERVATION"


def test_capability_is_never_edge_confidence_high() -> None:
    graph = se.twin_edges(_sbom(), algorithms={"openssl": ["AES-256-GCM"]})
    capability = next(edge for edge in graph["edges"] if edge["kind"] == "HAS_CAPABILITY")
    assert capability["confidence"] == "LOW"
    assert capability["evidence_type"] == "CAPABILITY"


def test_an_unobserved_artifact_has_no_path_to_a_workload() -> None:
    graph = se.twin_edges(_sbom(), deployments=[])
    assert not any(edge["kind"] in {"DEPLOYED_AS", "RUNS_AS"} for edge in graph["edges"])
    assert graph["unobserved_components"] == ["openssl"]
    assert "no observation reaches this artifact" in graph["statement"]


# ---------------------------------------------------------------- history -- #


def _versioned(version: str, sbom_id: str, created_at: date,
               *, extra: dict | None = None) -> se.SbomRecord:
    component = {"name": "openssl", "version": version, "crypto_relevant": True}
    component.update(extra or {})
    components = [component]
    if extra is not None and extra.get("with_libssl"):
        components.append({"name": "libssl", "version": version})
    return se.SbomRecord(sbom_id, _artifact(), tuple(components), created_at=created_at)


def test_a_series_of_snapshots_produces_a_timeline() -> None:
    report = se.history([
        _versioned("3.0.13", "SBOM-3", date(2026, 11, 2)),
        _versioned("3.0.11", "SBOM-1", date(2026, 10, 1)),
        _versioned("3.0.12", "SBOM-2", date(2026, 10, 20)),
    ])
    assert report["snapshots"] == ["SBOM-1", "SBOM-2", "SBOM-3"]
    assert len(report["transitions"]) == 2
    kinds = [change["kind"] for row in report["transitions"] for change in row["changes"]]
    assert kinds.count("VERSION_CHANGED") == 2
    assert report["components"]["openssl"][0]["version"] == "3.0.11"
    assert report["gap_days"] == 19


def test_identical_snapshots_change_nothing() -> None:
    report = se.history([_versioned("3.0.13", "SBOM-1", date(2026, 11, 1)),
                         _versioned("3.0.13", "SBOM-2", date(2026, 11, 2))])
    assert report["changed_transitions"] == 0
    assert "0 with no change" not in report["statement"]
    assert report["statement"].endswith("day(s)")  # the gap is still stated


def test_a_single_snapshot_is_a_timeline_of_one() -> None:
    report = se.history([_versioned("3.0.13", "SBOM-1", date(2026, 11, 1))])
    assert report["transitions"] == []
    assert report["snapshots"] == ["SBOM-1"]


# ------------------------------------------------------------- import guard -- #

def _cdx() -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "openssl", "version": "3.0.13",
                            "purl": "pkg:generic/openssl@3.0.13"}]}


def test_an_import_is_screened_and_labelled() -> None:
    from devsecops import sbom

    screening = sbom.guard_import(_cdx(), source="vendor-portal")
    assert screening["trust"] == "UNTRUSTED"
    assert screening["may_override"] is False
    assert screening["budget"]["verdict"] == "WITHIN_BUDGET"
    assert len(screening["content_hash"]) == 64
    marked = sbom.mark_imported(sbom.import_sbom(_cdx()))
    assert marked[0]["trust"] == "UNTRUSTED"
    assert marked[0]["may_override"] is False


def test_an_import_may_not_state_an_observed_fact() -> None:
    from devsecops import sbom

    with pytest.raises(ValueError, match="asserts deployment_identity"):
        sbom.guard_import({"bomFormat": "CycloneDX", "deployment_identity": "attacker-prod",
                           "components": []}, source="vendor-portal")


def test_an_import_over_the_budget_is_refused_before_it_is_read() -> None:
    from devsecops import sbom

    with pytest.raises(ValueError, match="exceeds the 0 limit"):
        sbom.guard_import(_cdx(), source="vendor-portal",
                          budget=se.ParserBudget(max_components=0))


# ------------------------------------------------------------ VEX governance -- #

def _vex_bom() -> dict:
    ref = "pkg:npm/left-pad@1.0.0"
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "library", "name": "left-pad", "version": "1.0.0",
                            "bom-ref": ref, "purl": ref}],
            "vulnerabilities": [{"id": "CVE-2024-0001", "ratings": [{"severity": "high"}],
                                 "affects": [{"ref": ref}]}]}


def _vex(**analysis) -> dict:
    from devsecops import sbom_vex

    base = {"state": "not_affected", "justification": "code_not_reachable"}
    base.update(analysis)
    return sbom_vex.statements(_vex_bom(), as_of=AS_OF,
                               analyses={"CVE-2024-0001": base})[0]


def test_a_governed_statement_is_complete() -> None:
    row = _vex(reviewer="Security Team", evidence_id="EVID-1",
               assessed_on="2026-01-01", expires_on="2027-01-01")
    assert row["state"] == "not_affected"
    assert row["governance"]["state"] == "COMPLETE"
    assert row["governance"]["expires_on"] == "2027-01-01"


def test_an_expired_statement_returns_the_finding_to_triage() -> None:
    row = _vex(reviewer="Security Team", evidence_id="EVID-1",
               assessed_on="2025-01-01", expires_on="2026-01-01")
    assert row["state"] == "in_triage"
    assert row["governance"]["expired"] is True
    assert row["governance"]["claimed_state"] == "not_affected"
    assert "lapsed on 2026-01-01" in row["detail"]


def test_an_ungoverned_statement_is_marked_incomplete() -> None:
    row = _vex()
    assert row["state"] == "not_affected"  # still the operator's claim
    assert row["governance"]["state"] == "INCOMPLETE"
    assert set(row["governance"]["missing"]) == {"reviewer", "evidence_id", "expires_on"}


def test_a_free_text_expiry_is_refused() -> None:
    with pytest.raises(ValueError, match="ISO date"):
        _vex(expires_on="next year")


def test_a_statement_cannot_expire_before_it_was_assessed() -> None:
    with pytest.raises(ValueError, match="before assessed_on"):
        _vex(assessed_on="2026-05-01", expires_on="2026-01-01")

"""Collector depth: runtime, network, Windows and the six BOMs (spec 92/93/94).

The point of these four matrices is that none of them may round a gap up. The
tests pin the specific overclaims each one exists to prevent:

* a runtime family whose producer is missing must not stay ``INVOCATION``;
* a protocol the build cannot read must appear as ``ABSENT``, not be omitted;
* the Windows candidate must answer **NO** to "is this a complete collector?";
* VBOM must never report deeper than ``DECLARED_ONLY``, whatever the estate holds;
* every route answers a capability matrix with no discovery run, and says the
  measured half is unobserved rather than printing zeros.
"""

from __future__ import annotations

import dataclasses

import pytest

from shared_models.estate_graph import EstateGraph, make_evidence

from api import bom_maturity as M
from api import network_protocols as N
from api import runtime_depth as R
from api import windows_collector as W

# --------------------------------------------------------------------------- #
# runtime depth
# --------------------------------------------------------------------------- #


def test_runtime_depth_separates_invocation_from_everything_weaker():
    doc = R.registry()
    depths = {row["id"]: row["depth"] for row in doc["paths"]}
    # the one family with real call-level instrumentation
    assert depths["openssl_native"] == R.DEPTH_INVOCATION
    # configured, not observed: a registered key is not a used key
    assert depths["hsm_provider"] == R.DEPTH_CONFIGURATION
    assert depths["kms_audit"] == R.DEPTH_CONFIGURATION
    # raised to process/library depth: the mapped libcrypto says the family is
    # present, and the family's own call-level observation type is still
    # accepted-but-unproduced
    for family in ("jvm", "dotnet_windows"):
        assert depths[family] == R.DEPTH_PROCESS_LIBRARY, family
        assert R.PATH_INDEX[family].ingest_only, family
        assert R.PATH_INDEX[family].producers, family
    # accepted by the engine, produced by nobody
    for family in ("go_runtime", "rust_runtime"):
        assert depths[family] == R.DEPTH_INGEST_ONLY, family
        assert R.PATH_INDEX[family].ingest_only, family
        assert R.PATH_INDEX[family].producers == (), family
    assert depths["interpreted"] == R.DEPTH_ABSENT


def test_every_declared_runtime_producer_resolves():
    absent = [
        (row["id"], producer["ref"], producer.get("reason"))
        for row in R.registry()["paths"]
        for producer in row["producers"]
        if not producer["present"]
    ]
    assert absent == []


def test_a_missing_producer_downgrades_the_family_by_itself(monkeypatch):
    broken = dataclasses.replace(R.PATH_INDEX["openssl_native"], producers=("nope:gone",))
    row = R._row(broken)
    assert row["declared_depth"] == R.DEPTH_INVOCATION
    assert row["depth"] == R.DEPTH_ABSENT
    assert row["notes"]


def test_every_family_states_what_it_cannot_claim():
    for row in R.registry()["paths"]:
        # The axiom of this whole module: installed is not executed.
        assert row["cannot_claim"]
        assert row["reads"]
        assert row["depth_meaning"]


def test_runtime_registry_claims_nothing_beyond_the_observed_families():
    doc = R.registry()
    assert doc["rollup"]["call_level_paths"] == 1
    assert "installed is not" in doc["axiom"].lower() or "OpenSSL installed" in doc["axiom"]
    assert "not a statement that every process" in doc["claim"]


def test_observed_store_separates_wire_from_invocation():
    class _Row(tuple):
        pass

    class _Db:
        def __init__(self, rows):
            self._rows = rows

        def execute(self, _stmt):
            rows = self._rows

            class _Result:
                def all(self):
                    return rows

            return _Result()

    # only wire + library rows: no invocation evidence exists
    observed = R.observe(
        _Db([("session", None, "host-a", 3), ("tls-library-risk", None, "host-a", 1)])
    )
    assert observed["state"] == "NO_INVOCATION_EVIDENCE"
    assert observed["invocation_rows"] == 0
    assert observed["wire_rows"] == 1
    assert observed["library_risk_rows"] == 1
    assert "not a statement that none ran" in observed["reason"]

    observed = R.observe(
        _Db([("crypto-call", {"source": "ld-preload", "function": "EVP_CipherInit_ex"}, "h", 7)])
    )
    assert observed["state"] == "INVOCATION_OBSERVED"
    assert observed["invocation_calls"] == 7

    assert R.observe(_Db([]))["state"] == "NO_RUNTIME_OBSERVATIONS"


def test_unreadable_store_is_not_evaluated_not_zero():
    class _Broken:
        def execute(self, _stmt):
            raise RuntimeError("database is locked")

    observed = R.observe(_Broken())
    assert observed["state"] == "NOT_EVALUATED"
    assert observed["rows"] is None
    assert "database is locked" in observed["reason"]


# --------------------------------------------------------------------------- #
# network protocols
# --------------------------------------------------------------------------- #


def test_tls_is_a_handshake_reader_and_offers_are_not_sessions():
    doc = N.registry()
    strengths = {row["id"]: row["strength"] for row in doc["protocols"]}
    assert strengths["tls"] == N.NEGOTIATED
    assert strengths["database"] == N.NEGOTIATED
    # an offer list is weaker than a handshake and must not be shown as one
    assert strengths["ssh"] == N.OFFERED
    assert strengths["ipsec"] == N.OFFERED
    assert strengths["passive"] == N.PASSIVE


def test_protocols_without_a_reader_are_listed_not_omitted():
    doc = N.registry()
    absent = {row["id"] for row in doc["protocols"] if row["strength"] == N.ABSENT}
    assert {"messaging", "proprietary", "service_mesh"} <= absent
    assert doc["rollup"]["absent"] == 3
    for row in doc["protocols"]:
        if row["strength"] == N.ABSENT:
            assert row["gaps"], row["id"]


def test_every_declared_protocol_producer_resolves():
    absent = [
        (row["id"], producer["ref"])
        for row in N.registry()["protocols"]
        for producer in row["producers"]
        if not producer["present"]
    ]
    assert absent == []


def test_a_protocol_whose_reader_disappears_reads_as_absent():
    broken = dataclasses.replace(N.PROTOCOL_INDEX["ssh"], producers=("nope:gone",))
    row = N._row(broken)
    assert row["declared_strength"] == N.OFFERED
    assert row["strength"] == N.ABSENT
    assert row["notes"]


def test_network_claim_is_per_protocol_not_estate_wide():
    doc = N.registry()
    assert "per protocol, never an estate-wide network number" in doc["claim"]
    assert doc["rollup"]["negotiated"] == 4
    assert doc["rollup"]["offered_only"] == 2


def test_tls_on_application_ports_extends_coverage_without_speaking_the_protocol():
    """The one real network extension: brokers/directories/DBs at the TLS layer."""
    doc = N.registry()
    row = next(item for item in doc["protocols"] if item["id"] == "app_tls_ports")
    assert row["strength"] == N.NEGOTIATED
    assert row["producers_present"] == len(row["producers"])
    assert "speaks TLS and nothing else" in row["cannot_claim"]
    # the message-layer protocols stay absent: transport coverage did not buy it
    messaging = next(item for item in doc["protocols"] if item["id"] == "messaging")
    assert messaging["strength"] == N.ABSENT
    assert any("app_tls_ports" in gap for gap in messaging["gaps"])


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #


def test_windows_answers_no_to_being_a_complete_collector():
    doc = W.registry()
    assert doc["verdict"]["complete_collector"] is False
    assert doc["verdict"]["answer"] == "NO"
    assert "substrate" in doc["verdict"]["reason"]
    assert doc["rollup"]["invocation_layers"] == 0


def test_every_windows_layer_declares_what_it_establishes():
    doc = W.registry()
    for row in doc["layers"]:
        assert row["establishes"] in W.STATE_MEANING or row["establishes"] in (
            W.SUBSTRATE,
            W.CONFIGURATION,
            W.INVOCATION,
        )
        assert row["cannot_claim"]
    absent = {row["id"] for row in doc["layers"] if row["state"] == W.ABSENT}
    # the two layers that would give invocation evidence are the ones missing
    assert {"schannel_events", "dotnet_clr"} <= absent
    # policy is now read, and reading it did not buy invocation evidence
    policy = next(row for row in doc["layers"] if row["id"] == "schannel_policy")
    assert policy["state"] == W.PARTIAL
    assert policy["establishes"] == W.CONFIGURATION
    assert policy["producers_present"] == 3
    assert "policy, not use" in policy["cannot_claim"]
    # reading the policy moved the layer, not the verdict
    assert doc["verdict"]["complete_collector"] is False
    assert doc["rollup"]["invocation_layers"] == 0


def test_schannel_policy_collector_is_real_and_states_its_boundary():
    """The one Windows gap that is closable without ETW — closed, not claimed away."""
    from inventory import windows_schannel as S

    report = S.evaluate(lambda path: None)
    # a stock host: nothing configured, and the report says exactly that
    assert report["offered_versions"] == []
    assert report["tls_floor"] is None
    assert "built-in" in report["tls_floor_basis"]
    # policy is never presented as a negotiated session
    assert "not a record of what any application negotiated" in report["meaning"]


def test_windows_producers_resolve_and_the_scm_candidate_is_substrate_only():
    doc = W.registry()
    absent = [
        (row["id"], producer["ref"])
        for row in doc["layers"]
        for producer in row["producers"]
        if not producer["present"]
    ]
    assert absent == []
    scm = next(row for row in doc["layers"] if row["id"] == "service_inventory")
    assert scm["establishes"] == W.SUBSTRATE
    assert "does not tell us what crypto" in scm["cannot_claim"]


# --------------------------------------------------------------------------- #
# six BOMs
# --------------------------------------------------------------------------- #


def _graph(*, with_vendor: bool = True) -> EstateGraph:
    graph = EstateGraph(estate="payments-bank")
    api = graph.add_asset("APPLICATION", "Payment API")
    graph.add_evidence(
        make_evidence(
            source="runtime-trace",
            evidence_type="RUNTIME_OBSERVED",
            target=api,
            layer="APPLICATION",
            facts={"algorithm": "AES", "key_size": 256, "role": "bulk-encryption"},
        )
    )
    if with_vendor:
        vendor = graph.add_asset("VENDOR", "VendorX", identity={"name": "VendorX"})
        graph.add_evidence(
            make_evidence(
                source="vendor-datasheet",
                evidence_type="VENDOR_DECLARED",
                target=vendor,
                layer="HSM",
                facts={"algorithm": "AES", "key_size": 256, "role": "bulk-encryption", "product": "X"},
            )
        )
    return graph


def test_cbom_reaches_observed_while_vbom_cannot():
    doc = M.measure(_graph())
    by_kind = {row["kind"]: row for row in doc["boms"]}
    assert by_kind["CBOM"]["depth"] == M.OBSERVED
    assert by_kind["VBOM"]["depth"] == M.DECLARED_ONLY
    # the ceiling is a property of what the projection consumes
    assert by_kind["VBOM"]["ceiling"] == M.DECLARED_ONLY
    assert by_kind["VBOM"]["at_ceiling"] is True


def test_a_bom_never_reports_deeper_than_its_ceiling():
    doc = M.measure(_graph())
    for row in doc["boms"]:
        assert M.RANK[row["depth"]] >= M.RANK[row["ceiling"]], row["kind"]


def test_an_unfed_projection_is_empty_not_failing():
    doc = M.measure(EstateGraph(estate="empty"))
    for row in doc["boms"]:
        assert row["depth"] == M.EMPTY
        assert row["components"] == 0
    assert doc["rollup"]["observed"] == 0
    assert doc["deepest"] == []


def test_components_without_evidence_are_unbacked_not_observed():
    graph = EstateGraph(estate="e")
    graph.add_asset("APPLICATION", "Orphan API")
    doc = M.measure(graph)
    by_kind = {row["kind"]: row for row in doc["boms"]}
    assert by_kind["TECHBOM"]["depth"] == M.UNBACKED
    assert by_kind["TECHBOM"]["unbacked_components"] == 1


def test_bom_maturity_computes_no_percentage_or_score():
    doc = M.measure(_graph())
    assert "no percentage is computed" in doc["claim"]
    assert not any("%" in str(row.get("depth")) for row in doc["boms"])
    assert set(doc["rollup"]) == {"boms", "by_depth", "observed", "at_ceiling"}


def test_the_six_boms_are_all_present_and_keep_kind_order():
    doc = M.measure(_graph())
    assert [row["kind"] for row in doc["boms"]] == ["CBOM", "SBOM", "TECHBOM", "NBOM", "HBOM", "VBOM"]


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
ROUTES = (
    "/api/v1/estate/evidence/discovery/runtime-depth",
    "/api/v1/estate/evidence/discovery/network-protocols",
    "/api/v1/estate/evidence/discovery/windows-collector",
    "/api/v1/estate/evidence/discovery/bom-maturity",
)


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/depth.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _headers(client):
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", ROUTES)
def test_depth_routes_require_auth(client, path):
    assert client.get(path).status_code == 401


def test_runtime_depth_answers_without_any_run(client):
    """Capability is a property of the build, so it survives an empty estate."""
    body = client.get(ROUTES[0], headers=_headers(client)).json()
    assert body["schema"] == R.SCHEMA
    assert body["rollup"]["paths"] == len(R.PATHS)
    assert body["observed"]["state"] in {"NO_RUNTIME_OBSERVATIONS", "NO_INVOCATION_EVIDENCE"}


def test_network_matrix_states_the_measured_half_is_unobserved(client):
    body = client.get(ROUTES[1], headers=_headers(client)).json()
    assert body["schema"] == N.SCHEMA
    assert body["measured"]["state"] == "NOT_OBSERVED"
    assert body["measured"]["reason"]
    assert body["measured"]["run_id"] is None
    # the crypto-bearing port table is served with the matrix, not hidden in code
    assert body["port_table"]["counts"]["ports"] >= 10
    assert body["port_table"]["counts"]["iana"] + body["port_table"]["counts"]["convention"] == (
        body["port_table"]["counts"]["ports"]
    )


def test_windows_matrix_answers_no_without_a_run(client):
    body = client.get(ROUTES[2], headers=_headers(client)).json()
    assert body["verdict"]["answer"] == "NO"
    assert body["measured"]["state"] == "NOT_OBSERVED"


def test_bom_maturity_without_a_snapshot_claims_nothing(client):
    body = client.get(ROUTES[3], headers=_headers(client)).json()
    assert body["state"] == "NOT_OBSERVED"
    assert body["boms"] == []
    assert body["reason"]


# --------------------------------------------------------------------------- #
# cross-matrix consistency: one surface registry, three deeper views
# --------------------------------------------------------------------------- #
def test_windows_surface_and_windows_matrix_agree():
    """The surface row and the layer matrix must not tell different stories.

    The surface registry models Windows at host granularity; the layer matrix
    models it per collection layer. Every layer collector the matrix knows about
    has to appear in the surface row, or the coverage screen would hide a
    collector this build actually ships.
    """
    from api import estate_surfaces as S

    surface = S.SURFACE_INDEX["windows_host"]
    layer_modules = {ref.split(":", 1)[0] for layer in W.LAYERS for ref in layer.producers}
    surface_modules = {ref.split(":", 1)[0] for ref in surface.detectors}
    missing = layer_modules - surface_modules
    assert missing == set(), f"windows collectors missing from the surface registry: {missing}"
    # and the surface must not claim call-level Windows evidence either
    assert "NOT_OBSERVED on Windows" in surface.cannot_claim
    assert surface.maturity == S.MATURITY_PARTIAL


def test_runtime_surface_and_runtime_matrix_agree():
    """The `runtime` surface is one row; the matrix says which families it means.

    The surface names the *aggregator* (`runtime.core.collector`), the matrix
    names the per-family producers. Both must live in the runtime package, and
    the surface must not claim more depth than the deepest family has.
    """
    from api import estate_surfaces as S

    surface = S.SURFACE_INDEX["runtime"]
    matrix_modules = {ref.split(":", 1)[0] for row in R.PATHS for ref in row.producers}
    assert matrix_modules <= {
        "runtime.agent.preload_trace",
        "runtime.agent.crypto_events",
        "runtime.agent.process_discovery",
        "api.estate_discovery",
        "cbom.kmip",
        "api.estate_kms",
        "inventory.cloud_kms",
        # the CLR-on-Windows family reaches the host through the Windows
        # collectors: mapped libcrypto here, registered providers there
        "inventory.windows_capi",
        "inventory.windows_cng",
    }
    assert {ref.split(":", 1)[0] for ref in surface.detectors} == {"runtime.core.collector"}
    # the surface's ceiling is PARTIAL, which is exactly what one call-level
    # family out of eight means
    assert surface.maturity == S.MATURITY_PARTIAL
    call_level = [row.id for row in R.PATHS if row.depth == R.DEPTH_INVOCATION]
    assert call_level == ["openssl_native"]
    assert "no eBPF/uprobe capture in this build" in surface.gaps


def test_network_surface_detectors_are_protocol_readers():
    """A banner parser is not a protocol reader, and the two views must agree.

    The network-device surface carries the SSH and cipher probes (both protocol
    readers) plus the Cisco banner plugin. That plugin is **not** in the protocol
    matrix on purpose: parsing a vendor banner says nothing about what the device
    negotiated, so counting it as protocol coverage would be the exact
    conflation the matrices exist to prevent.
    """
    from api import estate_surfaces as S

    surface = S.SURFACE_INDEX["network_device"]
    protocol_modules = {ref.split(":", 1)[0] for protocol in N.PROTOCOLS for ref in protocol.producers}
    surface_modules = {ref.split(":", 1)[0] for ref in surface.detectors}
    assert {"network_scanner.probing.ssh_kex", "network_scanner.probing.cipher_probe"} <= protocol_modules
    assert surface_modules & {"universal_vendor.plugins.network"} == {"universal_vendor.plugins.network"}
    assert not (surface_modules & {"universal_vendor.plugins.network"}) <= protocol_modules

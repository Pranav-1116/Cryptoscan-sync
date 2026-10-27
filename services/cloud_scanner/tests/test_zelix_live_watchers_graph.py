"""ZELNX Live engine tests — live key / certificate / network / k8s /
serverless watchers, live crypto dependency graph, continuous PQC
readiness (§8–§12, §16, §17).

Covers:
  §8  live KMS/key monitoring (9 change kinds, blast radius, no key
      material)
  §9  multi-cloud certificate watcher (CREATED/RENEWED/REPLACED/EXPIRED/
      REVOKED/ALGORITHM_CHANGED)
  §10 continuous network monitoring (10 change kinds + crypto paths)
  §11 continuous Kubernetes monitoring (EKS/AKS/GKE)
  §12 serverless live monitoring
  §16 live cloud crypto dependency graph (cross-provider edges)
  §17 continuous PQC readiness (migration priority)
"""

from __future__ import annotations

import pytest

from cloud_scanner.enterprise.live.cert_watcher import (
    CERT_EVENT_TO_KIND,
    MultiCloudCertificateWatcher,
)
from cloud_scanner.enterprise.live.event_schema import CloudEvent
from cloud_scanner.enterprise.live.key_monitor import (
    KEY_EVENT_TYPES,
    LiveKeyMonitor,
    is_key_event,
)
from cloud_scanner.enterprise.live.live_graph import (
    LiveCloudDependencyGraph,
    relation_for_event,
)
from cloud_scanner.enterprise.live.network_monitor import (
    NETWORK_EVENT_TYPES,
    LiveNetworkMonitor,
    is_network_event,
)
from cloud_scanner.enterprise.live.pqc_monitor import (
    ContinuousPQCReadinessMonitor,
    pqc_priority,
    pqc_status_for_algorithm,
)
from cloud_scanner.enterprise.live.simulation import LiveSimulationEngine
from cloud_scanner.enterprise.live.workload_monitors import (
    KubernetesLiveMonitor,
    ServerlessLiveMonitor,
)
from zelix_live_fixtures import (
    AWS_CERT,
    AWS_KEY,
    AZURE_CERT,
    GCP_CERT,
    GCP_KEY,
    make_live_engine,
)


def ev(event_type: str, resource_id: str, provider: str = "aws", **meta) -> CloudEvent:
    return CloudEvent(event_id=f"{provider}-{event_type}-{resource_id}",
                      provider=provider, event_type=event_type, change_type="",
                      resource_id=resource_id, resource_type="test",
                      provider_metadata=meta, timestamp="2026-05-01T10:00:00Z")


# ------------------------------------------------------------------------- §8

class TestLiveKeyMonitor:
    def test_all_spec_change_kinds_covered(self):
        expected = {"KEY_CREATED", "KEY_DISABLED", "KEY_ENABLED", "KEY_ROTATED",
                    "KEY_SCHEDULED_FOR_DELETION", "KEY_POLICY_CHANGED",
                    "KEY_PERMISSION_CHANGED", "KEY_ALGORITHM_CHANGED",
                    "KEY_PROTECTION_LEVEL_CHANGED"}
        assert set(KEY_EVENT_TYPES) == expected

    def test_key_blast_radius_flow(self):
        deps = [{"resource": "payments-api", "kind": "application"},
                {"resource": "dataset-pay", "kind": "dataset"},
                {"resource": "lb-api", "kind": "network"}]
        monitor = LiveKeyMonitor(find_dependencies=lambda key: deps,
                                 find_access=lambda key: [{"identity": "svc-a"}])
        radius = monitor.watch(ev("KEY_POLICY_CHANGED", AWS_KEY))
        assert radius.key_id == AWS_KEY
        assert radius.applications == ["payments-api"]
        assert radius.datasets == ["dataset-pay"]
        assert radius.network_services == ["lb-api"]
        assert radius.access_bindings == ["svc-a"]
        assert radius.severity == "HIGH"  # policy change

    def test_key_event_filter(self):
        assert is_key_event("KEY_ROTATED")
        assert not is_key_event("CERTIFICATE_RENEWED")
        assert LiveKeyMonitor().watch(ev("CERTIFICATE_RENEWED", "c1")) is None

    def test_no_key_material_ever_touched(self):
        captured: list = []
        def find_dependencies(key_id):
            captured.append(key_id)
            return []
        monitor = LiveKeyMonitor(find_dependencies=find_dependencies)
        monitor.watch(ev("KEY_ROTATED", AWS_KEY))
        # the monitor only asks for dependencies/access — never key material
        assert captured == [AWS_KEY]
        radius = monitor.impacts()[0]
        assert "material" not in radius.to_dict()
        assert "private_key" not in radius.to_dict()

    def test_rotation_with_no_deps_is_low(self):
        monitor = LiveKeyMonitor(find_dependencies=lambda key: [])
        radius = monitor.watch(ev("KEY_ROTATED", "key-rot"))
        assert radius.severity == "LOW"


# ------------------------------------------------------------------------- §9

class TestCertificateWatcher:
    def test_all_change_kinds_covered(self):
        assert set(CERT_EVENT_TO_KIND.values()) == {"CREATED", "RENEWED", "REPLACED",
                                                    "EXPIRED", "REVOKED",
                                                    "ALGORITHM_CHANGED"}

    @pytest.mark.parametrize("event_type,kind", [
        ("CERTIFICATE_CREATED", "CREATED"),
        ("CERTIFICATE_RENEWED", "RENEWED"),
        ("CERTIFICATE_REPLACED", "REPLACED"),
        ("CERTIFICATE_EXPIRED", "EXPIRED"),
        ("CERTIFICATE_REVOKED", "REVOKED"),
        ("CERTIFICATE_ALGORITHM_CHANGED", "ALGORITHM_CHANGED"),
    ])
    def test_change_kinds(self, event_type, kind):
        watcher = MultiCloudCertificateWatcher(find_consumers=lambda c: [])
        change = watcher.watch(ev(event_type, AWS_CERT))
        assert change.change_kind == kind

    def test_expired_cert_is_critical(self):
        watcher = MultiCloudCertificateWatcher(
            find_consumers=lambda c: [{"resource": "lb-api", "kind": "load_balancer"}])
        change = watcher.watch(ev("CERTIFICATE_EXPIRED", AWS_CERT))
        assert change.severity == "CRITICAL"
        assert change.tls_endpoints == ["lb-api"]

    def test_multi_cloud_same_watcher(self):
        consumers = {
            AWS_CERT: [{"resource": "lb-aws", "kind": "load_balancer"}],
            AZURE_CERT: [{"resource": "appgw", "kind": "load_balancer"}],
            GCP_CERT: [{"resource": "lb-gcp", "kind": "load_balancer"}],
        }
        watcher = MultiCloudCertificateWatcher(find_consumers=lambda c: consumers.get(c, []))
        for cert, provider in ((AWS_CERT, "aws"), (AZURE_CERT, "azure"), (GCP_CERT, "gcp")):
            change = watcher.watch(ev("CERTIFICATE_REPLACED", cert, provider=provider))
            assert change.provider == provider
        assert watcher.summary()["changes"] == 3

    def test_revoked_severity(self):
        watcher = MultiCloudCertificateWatcher(find_consumers=lambda c: [])
        assert watcher.watch(ev("CERTIFICATE_REVOKED", AWS_CERT)).severity == "CRITICAL"


# ------------------------------------------------------------------------ §10

class TestNetworkMonitor:
    def test_all_network_change_kinds_covered(self):
        expected = {"NEW_PUBLIC_ENDPOINT", "NEW_PRIVATE_ENDPOINT",
                    "LOAD_BALANCER_CHANGE", "TLS_TERMINATION_CHANGE",
                    "API_GATEWAY_CHANGE", "VPN_CHANGE", "ROUTE_CHANGE",
                    "SECURITY_POLICY_CHANGE", "NETWORK_PEERING_CHANGE",
                    "CROSS_CLOUD_CONNECTION"}
        assert set(NETWORK_EVENT_TYPES) == expected
        assert is_network_event("VPN_CHANGE")
        assert not is_network_event("KEY_ROTATED")

    def test_tls_termination_finds_crypto_paths(self):
        monitor = LiveNetworkMonitor(find_paths=lambda rid: [["lb-api", "TLS1.2", AWS_CERT]])
        change = monitor.watch(ev("TLS_TERMINATION_CHANGE", "lb-api"))
        assert change.severity == "HIGH"
        assert change.affected_paths == [["lb-api", "TLS1.2", AWS_CERT]]
        assert change.risk_recalculated is True

    def test_public_endpoint_severity(self):
        monitor = LiveNetworkMonitor(find_paths=lambda rid: [])
        change = monitor.watch(ev("NEW_PUBLIC_ENDPOINT", "ep-1"))
        assert change.severity == "HIGH"

    def test_cross_cloud_connection_kind(self):
        monitor = LiveNetworkMonitor(find_paths=lambda rid: [])
        change = monitor.watch(ev("CROSS_CLOUD_CONNECTION", "conn-1", provider="aws"))
        assert change.event_type == "CROSS_CLOUD_CONNECTION"


# ------------------------------------------------------------------------ §11

class TestKubernetesMonitor:
    def test_all_k8s_change_kinds(self):
        expected = {"K8S_NEW_NAMESPACE", "K8S_NEW_WORKLOAD", "K8S_NEW_INGRESS",
                    "K8S_CERTIFICATE_CHANGED", "K8S_MTLS_CHANGED",
                    "K8S_MESH_CHANGED", "K8S_IMAGE_CHANGED",
                    "K8S_CRYPTO_DEPENDENCY_CHANGED"}
        assert {t for t in _k8s_event_names()} == expected

    def test_workload_identity_resolution(self):
        monitor = KubernetesLiveMonitor(
            resolve_identity=lambda rid: "workload:payments-svc",
            find_crypto_dependencies=lambda rid: [AWS_KEY, AWS_CERT])
        change = monitor.watch(ev("K8S_MTLS_CHANGED", "eks-prod-1",
                                  cluster_id="eks-prod-1", namespace="payments"))
        assert change.workload_identity == "workload:payments-svc"
        assert AWS_KEY in change.crypto_dependencies
        assert change.targeted_reevaluation is True

    def test_provider_agnostic(self):
        monitor = KubernetesLiveMonitor()
        for provider in ("aws", "azure", "gcp"):
            change = monitor.watch(ev("K8S_NEW_WORKLOAD", f"w-{provider}",
                                      provider=provider))
            assert change.provider == provider


def _k8s_event_names():
    from cloud_scanner.enterprise.live.workload_monitors import K8S_EVENT_TYPES
    return K8S_EVENT_TYPES


# ------------------------------------------------------------------------ §12

class TestServerlessMonitor:
    def test_all_serverless_change_kinds(self):
        expected = {"SERVERLESS_NEW_DEPLOYMENT", "SERVERLESS_NEW_VERSION",
                    "SERVERLESS_DEPENDENCY_CHANGE", "SERVERLESS_RUNTIME_CHANGE",
                    "SERVERLESS_ENV_CONFIG_CHANGE", "SERVERLESS_KEY_REF_CHANGE",
                    "SERVERLESS_CERT_REF_CHANGE"}
        from cloud_scanner.enterprise.live.workload_monitors import SERVERLESS_EVENT_TYPES
        assert set(SERVERLESS_EVENT_TYPES) == expected

    def test_key_ref_change_triggers_analysis(self):
        def analyze(event):
            return {"runtime": "nodejs20",
                    "crypto_libraries": ["node-forge"],
                    "key_references": [AWS_KEY]}
        monitor = ServerlessLiveMonitor(analyze=analyze)
        change = monitor.watch(ev("SERVERLESS_KEY_REF_CHANGE", "lambda-pay"))
        assert change.crypto_libraries == ["node-forge"]
        assert change.key_references == [AWS_KEY]
        assert change.cbom_updated is True

    def test_ignores_non_serverless(self):
        assert ServerlessLiveMonitor().watch(ev("KEY_ROTATED", "k1")) is None


# ------------------------------------------------------------------------ §16

class TestLiveDependencyGraph:
    def test_upsert_delete_count(self):
        graph = LiveCloudDependencyGraph()
        graph.upsert("payments-api", AWS_KEY, "USES_KEY", provider="aws")
        graph.upsert("payments-api", AWS_CERT, "USES_CERTIFICATE", provider="aws")
        graph.upsert("analytics-svc", GCP_KEY, "USES_KEY", provider="gcp")
        assert graph.count() == 3
        assert len(graph.by_relation("USES_KEY")) == 2
        assert graph.delete("payments-api", AWS_KEY, "USES_KEY")
        assert graph.count() == 2

    def test_event_auto_wire_edge(self):
        graph = LiveCloudDependencyGraph()
        event = ev("TLS_TERMINATION_CHANGE", "lb-api", depends_on=AWS_CERT)
        relation = graph.apply_event(event)
        assert relation == "TERMINATES_TLS"
        assert graph.count() == 1
        edge = graph.edges()[0]
        assert edge.source == "lb-api"
        assert edge.target == AWS_CERT
        assert edge.provider == "aws"

    def test_dependents_transitive(self):
        graph = LiveCloudDependencyGraph()
        graph.upsert("payments-api", AWS_KEY, "USES_KEY")
        graph.upsert("lb-api", "payments-api", "DEPENDS_ON")
        graph.upsert("front-door", "lb-api", "DEPENDS_ON")
        assert set(graph.dependents(AWS_KEY)) == {"payments-api", "lb-api", "front-door"}
        assert graph.dependents(AWS_KEY, transitive=False) == ["payments-api"]

    def test_relation_hints(self):
        assert relation_for_event("KEY_ROTATED") == "USES_KEY"
        assert relation_for_event("CERTIFICATE_CHANGED") == "USES_CERTIFICATE"
        assert relation_for_event("VPN_CHANGE") == "CONNECTS_TO"

    def test_delete_all_on_resource_removal(self):
        graph = LiveCloudDependencyGraph()
        graph.upsert("payments-api", AWS_KEY, "USES_KEY")
        graph.upsert("payments-api", AWS_CERT, "USES_CERTIFICATE")
        assert graph.delete_all("payments-api") == 2
        assert graph.count() == 0


# ------------------------------------------------------------------------ §17

class TestContinuousPQCReadiness:
    def test_algorithm_status(self):
        assert pqc_status_for_algorithm("ML-KEM-768") == "PQC_READY"
        assert pqc_status_for_algorithm("RSA-2048") == "NOT_READY"
        assert pqc_status_for_algorithm("") == "UNKNOWN"

    def test_rsa_banking_public_gets_high_priority(self):
        priority = pqc_priority(algorithm="RSA-2048", internet_exposed=True,
                                criticality="HIGH", pqc_status="NOT_READY")
        assert priority in ("HIGH", "CRITICAL")

    def test_internal_dev_storage_lower_priority(self):
        priority = pqc_priority(algorithm="RSA-2048", internet_exposed=False,
                                criticality="STANDARD", pqc_status="NOT_READY")
        assert priority == "LOW"

    def test_pqc_ready_is_low(self):
        priority = pqc_priority(algorithm="ML-KEM-768", internet_exposed=True,
                                criticality="CRITICAL", pqc_status="PQC_READY")
        assert priority == "LOW"

    def test_monitor_watches_crypto_events(self):
        monitor = ContinuousPQCReadinessMonitor(
            detect_algorithm=lambda e: e.provider_metadata.get("algorithm", ""))
        eval_ = monitor.watch(ev("CERTIFICATE_CREATED", AWS_CERT,
                                 algorithm="RSA-2048", public_internet_exposed=True,
                                 criticality="HIGH"))
        assert eval_.pqc_status == "NOT_READY"
        assert eval_.migration_priority in ("HIGH", "CRITICAL")
        assert monitor.watch(ev("NEW_PUBLIC_ENDPOINT", "ep-1")) is None

    def test_engine_wires_pqc(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        # RSA-2048 AWS cert + EC-P256 Azure cert + RSA-3072 GCP cert evaluated
        assert len(report.pqc["evaluations"]) >= 3
        algorithms = {e["algorithm"] for e in report.pqc["evaluations"]}
        assert "RSA-2048" in algorithms


# ------------------------------------------------- live simulation bridge

class TestLiveSimulationEngine:
    def test_evaluate_change_finds_dependents(self):
        graph = LiveCloudDependencyGraph()
        graph.upsert("payments-api", AWS_KEY, "USES_KEY")
        graph.upsert("lb-api", "payments-api", "DEPENDS_ON")
        simulator = LiveSimulationEngine(graph=graph)
        evaluation = simulator.evaluate_change(
            change_id="rot-1", change_kind="KEY_ROTATION", target=AWS_KEY,
            steps=[{"action": "rotate", "target": AWS_KEY}])
        assert "payments-api" in evaluation.affected_assets
        assert "lb-api" in evaluation.affected_assets
        assert evaluation.verdict == "COMPATIBLE"
        assert evaluation.path_simulations[0]["paths_evaluated"] == 0

    def test_path_simulator_verdict_passthrough(self):
        graph = LiveCloudDependencyGraph()
        graph.upsert("app", AWS_CERT, "USES_CERTIFICATE")
        simulator = LiveSimulationEngine(
            graph=graph,
            path_simulator=lambda steps: {"verdict": "INCOMPATIBLE",
                                          "paths_evaluated": 2,
                                          "blocked": ["tls1.0-client"]})
        evaluation = simulator.evaluate_change(
            change_id="cert-1", change_kind="CERTIFICATE_REPLACEMENT",
            target=AWS_CERT, steps=[{"action": "replace", "target": AWS_CERT}])
        assert evaluation.verdict == "INCOMPATIBLE"
        assert evaluation.path_simulations[0]["paths_evaluated"] == 2
        assert evaluation.notes == ["1 dependents re-evaluated"]

"""§1 Universal Discovery Engine tests — asset normalization,
cross-domain correlation, verification, monitor plan."""

from __future__ import annotations

from cloud_scanner.core.scanner import CloudScanner
from universal_platform.assets import ASSET_TYPES, normalize_asset
from universal_platform.discovery import UniversalDiscoveryEngine


def _domains() -> dict:
    return {
        "network": {"assets": [
            {"asset_type": "load_balancer", "identity": "lb-01",
             "ip": "10.0.0.5", "certificates": ["payments.internal"]},
            {"asset_type": "router", "identity": "rtr-core-1",
             "ip": "10.0.0.1"},
        ]},
        "crypto": {
            "observations": [
                {"algorithm": "RSA", "operation": "sign", "key_size": 2048},
                {"algorithm": "ML-KEM-768", "operation": "key_exchange"},
            ],
            "certificates": [
                {"subject": "payments.internal",
                 "signature_algorithm": "RSA-PSS"},
            ],
        },
        "hardware": {"assets": [
            {"asset_type": "hsm", "identity": "hsm-pci-01",
             "firmware": "7.2", "crypto_capabilities": ["AES", "RSA"]},
        ]},
        "cloud": {"assets": [
            {"asset_type": "cloud_resource", "identity": "aws-elb-prod",
             "provider": "aws", "certificates": ["payments.internal"]},
        ]},
        "vendor": {"assets": [
            {"asset_type": "vendor", "identity": "Acme",
             "pqc_support": "ml-kem"},
        ]},
    }


def test_asset_catalog_covers_spec_domains():
    assert ASSET_TYPES["ip_range"] == "network"
    assert ASSET_TYPES["hsm"] == "hardware"
    assert ASSET_TYPES["cloud_resource"] == "cloud"
    assert ASSET_TYPES["certificate"] == "crypto"
    assert ASSET_TYPES["vendor"] == "vendor"
    assert len(ASSET_TYPES) >= 40


def test_normalize_asset_picks_identity_and_domain():
    asset = normalize_asset({"asset_type": "firewall", "hostname": "fw-1",
                             "ip": "10.0.0.2"})
    assert asset.domain == "network"
    assert asset.identity == "fw-1"
    assert asset.status == "ACTIVE"


def test_discover_runs_all_domains_and_correlates():
    report = UniversalDiscoveryEngine().run(_domains())
    assert report["sources_run"] == ["network", "crypto", "hardware",
                                     "cloud", "vendor"]
    # every §1 domain contributed assets
    domains = {a["domain"] for a in report["assets"]}
    assert domains == {"network", "crypto", "hardware", "cloud", "vendor"}

    # certificate ↔ load balancer and cloud service (uses_cert)
    kinds = {r["kind"] for r in report["relationships"]}
    assert "uses_cert" in kinds
    cert_links = [r for r in report["relationships"]
                  if r["from"] == "payments.internal"]
    assert cert_links, "certificate must be linked to its consumers"
    assert report["verified"]["crypto:payments.internal"] is True


def test_real_cloud_scanner_report_maps_identified_findings(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_kms_key" "payments" { customer_master_key_spec = "RSA_2048" }\n'
        'resource "aws_s3_bucket" "logs" { bucket = "logs" }\n'
    )
    cloud_report = CloudScanner(live=False).scan_filesystem(tmp_path)
    assert cloud_report["resources"] == 2
    assert isinstance(cloud_report["resources"], int)
    assert all(f["metadata"]["resource"] and f["source"]["file_path"] for f in cloud_report["findings"])

    report = UniversalDiscoveryEngine().run({"cloud": cloud_report})
    assert report["asset_count"] == 2
    assets = {a["identity"]: a for a in report["assets"]}
    assert set(assets) == {"aws_kms_key.payments", "aws_s3_bucket.logs"}
    assert all(a["asset_type"] == "cloud_resource" and a["domain"] == "cloud" for a in assets.values())
    assert all(a["sources"] and a["evidence"] for a in assets.values())
    assert assets["aws_kms_key.payments"]["attributes"]["provider"] == "AWS"
    assert assets["aws_kms_key.payments"]["evidence"][0]["source"]["file_path"] == str(tmp_path / "main.tf")
    assert report["partial_coverage"] == {}


def test_cloud_legacy_asset_and_resource_lists_still_work():
    for key in ("assets", "resources"):
        report = UniversalDiscoveryEngine().run({"cloud": {key: [
            {"asset_type": "cloud_resource", "identity": "aws-resource-1", "sources": ["legacy"]},
        ]}})
        assert report["asset_count"] == 1
        assert report["assets"][0]["identity"] == "aws-resource-1"


def test_cloud_scalar_count_and_unidentified_findings_are_partial_not_assets():
    engine = UniversalDiscoveryEngine()
    summary = engine.run({"cloud": {"resources": 3}})
    assert summary["asset_count"] == 0
    assert summary["sources_run"] == ["cloud"]
    assert summary["partial_coverage"]["cloud"]["status"] == "PARTIAL"
    assert engine.run({"cloud": {"resources": 0, "findings": []}})["partial_coverage"] == {}

    unknown = engine.run({"cloud": {
        "resources": 4,
        "findings": [
            {"algorithm": "AES", "metadata": {"cloud_provider": "AWS"},
             "source": {"type": "AWS_KMS_KEY", "file_path": "aws://region/kms/key"}},
            {"metadata": {"resource": "UNKNOWN"},
             "source": {"type": "AWS_KMS_KEY", "file_path": "aws://region/kms/unknown"}},
            {"metadata": {"resource": "key-without-source"}, "source": {}},
            {"metadata": {"resource": "key-unknown-type"},
             "source": {"type": "UNKNOWN", "file_path": "aws://region/kms/key"}},
        ],
    }})
    assert unknown["asset_count"] == 0
    assert unknown["partial_coverage"]["cloud"]["status"] == "PARTIAL"


def test_verify_marks_unknown_types_suspect():
    engine = UniversalDiscoveryEngine()
    engine.discover({"network": {"assets": [
        {"asset_type": "mystery_box", "identity": "x1", "sources": ["n"]},
    ]}}).verify()
    asset = list(engine.assets.values())[0]
    assert asset.status == "SUSPECT"
    assert engine.verified[("UNKNOWN", "x1")] is False  # domain honest


def test_monitor_plan_per_domain():
    engine = UniversalDiscoveryEngine().discover(_domains()).monitor(120)
    domains = {p["domain"] for p in engine.monitor_plan}
    assert domains == {"network", "crypto", "hardware", "cloud", "vendor"}
    assert all(p["cadence_seconds"] == 120 for p in engine.monitor_plan)

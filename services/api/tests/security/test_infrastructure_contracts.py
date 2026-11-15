"""Infrastructure contracts: the deployment surface stays complete and honest.

Pins the pieces of the infrastructure spec that live as repo artifacts:
namespace resource ceilings (quotas prevent resource exhaustion), the Helm
chart (repeatable Kubernetes install), and the offline bundle manifest (an
isolated bank network must install without a permanent external
connection). Config that silently rots is config that fails at 02:00 on the
bank's cluster.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))


# ------------------------------------------------------------- resource quota

class TestResourceExhaustionIsACeilingNotAWeatherEvent:
    def test_the_namespace_quota_and_limits_exist(self):
        text = (ROOT / "k8s" / "app" / "46-resource-quota.yaml").read_text()
        assert "kind: ResourceQuota" in text
        assert "kind: LimitRange" in text

    def test_the_quota_caps_compute_pods_and_storage(self):
        text = (ROOT / "k8s" / "app" / "46-resource-quota.yaml").read_text()
        for key in ("requests.cpu", "requests.memory", "limits.cpu",
                    "limits.memory", "pods", "requests.storage"):
            assert key in text, f"quota does not cap {key}"
        # a LimitRange with defaults means a manifest that forgets
        # `resources:` still runs inside the plan
        assert "default:" in text and "max:" in text


# ----------------------------------------------------------------- helm chart

class TestTheHelmChartIsARepeatableInstall:
    @pytest.fixture(scope="class")
    def chart(self):
        base = ROOT / "k8s" / "helm" / "cryptoscan"
        return {
            "chart": (base / "Chart.yaml").read_text(),
            "values": (base / "values.yaml").read_text(),
            "templates": {p.name: p.read_text()
                          for p in (base / "templates").iterdir() if p.is_file()},
        }

    def test_it_declares_itself_and_needs_no_chart_dependencies(self, chart):
        assert "name: cryptoscan" in chart["chart"]
        assert "apiVersion: v2" in chart["chart"]
        assert "dependencies:" not in chart["chart"], (
            "a chart with dependencies needs a repo the bank cannot reach")

    def test_images_come_from_values_never_a_public_registry(self, chart):
        # templates may only interpolate the repository/tag — a hardcoded
        # image in a template bypasses the bank's mirror
        for name, text in chart["templates"].items():
            if "kind: Deployment" in text:
                assert ".Values" in text.split("image:")[1].split("\n")[0], (
                    f"{name} hardcodes an image instead of reading values")
        assert "pullPolicy: IfNotPresent" in chart["values"]

    def test_the_chart_ships_the_quota_and_worker_autoscaling(self, chart):
        assert "kind: ResourceQuota" in chart["templates"]["resource-quota.yaml"]
        assert "kind: HorizontalPodAutoscaler" in chart["templates"]["worker-deployment.yaml"]
        assert "maxUnavailable: 0" in chart["templates"]["api-deployment.yaml"], (
            "the API tier must roll without an update becoming an outage")


# -------------------------------------------------------------- offline bundle

class TestTheAirGapBundleIsMechanicalNotAMemoryExercise:
    @pytest.fixture(scope="class")
    def doc(self):
        import offline_bundle
        return offline_bundle.manifest()

    def test_it_names_everything_an_isolated_install_needs(self, doc):
        assert doc["container_images_external"], "runtime images must be staged"
        # the stacks run on these; their absence means the compose walk broke
        joined = " ".join(doc["container_images_external"])
        for image in ("postgres", "neo4j", "nginx"):
            assert image in joined
        assert "cryptoscan-api" in doc["container_images_first_party"]
        assert any(p.startswith("fastapi==") for p in doc["python_pins"])
        assert doc["repo_files"], "install-time files must be hashed"

    def test_repo_files_are_hashed_for_tamper_evidence(self, doc):
        for rel, meta in doc["repo_files"].items():
            assert len(meta["sha256"]) == 64, rel
        assert "requirements.lock.txt" in doc["repo_files"]
        assert "docs/admin-guide/air-gap-install.md" in doc["repo_files"]

    def test_verify_reports_completeness_and_refuses_the_incomplete(self, doc, tmp_path):
        import offline_bundle
        staged = tmp_path / "usb"
        # stage everything the manifest hashes
        for rel in doc["repo_files"]:
            target = staged / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / rel).read_bytes())
        report = offline_bundle.verify(doc, staged)
        assert report["complete"] is True
        assert report["missing"] == [] and report["tampered"] == []

        (staged / "requirements.lock.txt").write_text("tampered")
        report = offline_bundle.verify(doc, staged)
        assert report["complete"] is False
        assert report["tampered"] and report["tampered"][0]["file"] == "requirements.lock.txt"
        assert "refuse to install" in report["verdict"]

    def test_verify_names_missing_artifacts_instead_of_skipping_them(self, doc, tmp_path):
        import offline_bundle
        report = offline_bundle.verify(doc, tmp_path / "empty")
        assert report["complete"] is False
        assert set(report["missing"]) == set(doc["repo_files"])

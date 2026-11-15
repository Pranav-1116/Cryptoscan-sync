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
        # image in a template bypasses the bank's mirror. The kind is matched
        # at the document level: a ScaledObject that only *references* a
        # Deployment in scaleTargetRef is not a workload template.
        import re as _re

        for name, text in chart["templates"].items():
            if _re.search(r"^kind: Deployment\s*$", text, _re.MULTILINE):
                assert "image:" in text, f"{name} declares a Deployment but ships no image"
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


# ---------------------------------------------------------------------------
# TLS/mTLS row (Critical): "Enable TLS/mTLS to protect internal and external
# communication." The gateways must demand client certificates signed by the
# bank's CA — configuration, not commentary.
# ---------------------------------------------------------------------------

REPO = ROOT  # the repository root this suite already locates

from api.routers import metrics as metrics_mod  # noqa: E402


class TestMTLSContracts:
    ENVLOY = REPO / "deploy" / "stack" / "envoy" / "envoy.yaml"
    NGINX = REPO / "deploy" / "ha" / "nginx.conf"

    def test_envoy_demands_client_certificates_at_the_edge(self):
        text = self.ENVLOY.read_text()
        assert "require_client_certificate: true" in text
        assert "validation_context" in text
        assert "trusted_ca" in text and "client-ca.crt" in text
        # and the same protection on the internal hop (service-to-service)
        assert "UpstreamTlsContext" in text

    def test_ha_nginx_verifies_client_certificates(self):
        text = self.NGINX.read_text()
        # real directives, not commented-out suggestions
        active = [ln for ln in text.splitlines()
                  if ln.strip().startswith("ssl_verify_client")]
        assert any("on" in ln for ln in active), text
        assert any("ssl_client_certificate" in ln and not ln.strip().startswith("#")
                   for ln in text.splitlines())


# ---------------------------------------------------------------------------
# Blue-green row (High — "safer upgrades"): a real state machine with the
# safety rules enforced, plus the runbook.
# ---------------------------------------------------------------------------


class TestBlueGreenContracts:
    SCRIPT = REPO / "scripts" / "blue_green.py"
    RUNBOOK = REPO / "docs" / "runbooks" / "blue-green-upgrade.md"

    @pytest.fixture()
    def orchestrator(self, tmp_path):
        import importlib.util

        spec = importlib.util.spec_from_file_location("blue_green", self.SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        class FakeDriver:
            def __init__(self):
                self.running = {"blue": True, "green": False}
                self.healthy = {"blue": True, "green": True}
                self.current = "blue"
                self.flips: list[str] = []

            def start(self, slot):
                self.running[slot] = True

            def stop(self, slot):
                self.running[slot] = False

            def health(self, slot):
                return self.running.get(slot) and self.healthy.get(slot, False)

            def activate(self, slot):
                self.current = slot
                self.flips.append(slot)

            def active(self):
                return self.current

        return mod.BlueGreen(FakeDriver())

    def test_activation_refuses_an_unhealthy_slot(self, orchestrator):
        orchestrator.driver.healthy["green"] = False
        report = orchestrator.activate("green")
        assert report.get("refused"), report
        assert orchestrator.driver.active() == "blue"  # never flipped blind

    def test_failed_verify_rolls_back_automatically(self, orchestrator):
        orchestrator.driver.start("green")
        assert orchestrator.activate("green")["active"] == "green"
        orchestrator.driver.healthy["green"] = False  # the release is bad
        report = orchestrator.verify("green")
        assert report["verified"] is False
        assert report["rolled_back_to"] == "blue"
        assert orchestrator.driver.active() == "blue"

    def test_prepare_stops_a_slot_that_fails_its_health_check(self, orchestrator):
        orchestrator.driver.healthy["green"] = False
        report = orchestrator.prepare("green")
        assert report.get("refused"), report
        assert orchestrator.driver.running["green"] is False
        assert orchestrator.driver.active() == "blue"

    def test_rollback_names_where_it_went(self, orchestrator):
        orchestrator.driver.start("green")
        orchestrator.activate("green")
        report = orchestrator.rollback()
        assert report["to"] == "blue" and report["active"] == "blue"

    def test_dry_run_touches_nothing(self, orchestrator):
        before = (orchestrator.driver.current, list(orchestrator.driver.flips))
        orchestrator.prepare("green", dry_run=True)
        orchestrator.activate("green", dry_run=True)
        orchestrator.verify("green", dry_run=True)
        orchestrator.rollback(dry_run=True)
        assert (orchestrator.driver.current, orchestrator.driver.flips) == before

    def test_the_runbook_is_beside_the_script(self):
        assert self.SCRIPT.exists() and self.RUNBOOK.exists()
        doc = self.RUNBOOK.read_text()
        for marker in ("prepare", "activate", "verify", "rollback", "undo"):
            assert marker in doc


# ---------------------------------------------------------------------------
# IaC row: "Use Ansible/Terraform where suitable." Repeatable installation
# that never reaches the internet and refuses unverified releases.
# ---------------------------------------------------------------------------


class TestAnsibleContracts:
    ANSIBLE = REPO / "deploy" / "ansible"

    def test_playbook_and_roles_exist(self):
        site = (self.ANSIBLE / "site.yml").read_text()
        for role in ("common", "runtime", "cryptoscan", "backup"):
            assert (self.ANSIBLE / "roles" / role / "tasks" / "main.yml").exists()
            assert f"- {role}" in site
        assert (self.ANSIBLE / "inventory.example.ini").exists()

    def test_installation_refuses_unverified_releases(self):
        tasks = (self.ANSIBLE / "roles" / "cryptoscan" / "tasks" / "main.yml").read_text()
        assert "manifest.sig" in tasks
        assert "refuse to install an unverified release" in tasks

    def test_secrets_are_referenced_not_valued(self):
        env = (self.ANSIBLE / "roles" / "cryptoscan" / "templates" / "env.j2").read_text()
        assert "_FILE=" in env
        assert "PASSWORD=" not in env.replace("PASSWORD_FILE=", "")

    def test_backup_automation_is_installed_not_advertised(self):
        tasks = (self.ANSIBLE / "roles" / "backup" / "tasks" / "main.yml").read_text()
        assert "cryptoscan-backup.timer" in tasks


# ---------------------------------------------------------------------------
# Queue-depth signal: the worker autoscaler and the operator need the same
# number — the pending backlog, the ceiling, and the refusals.
# ---------------------------------------------------------------------------


class TestQueueDepthSignal:
    def test_queue_gauges_expose_depth_limit_and_refusals(self, monkeypatch):
        import contextlib

        from api.routers import binary_intelligence as bi_mod

        fake = {
            "pending": 7,
            "refused_total": 3,
            "failed_total": 1,
            "limits": {"max_queue_depth": 1000},
        }
        monkeypatch.setattr(bi_mod.WORKER_QUEUE, "as_dict", lambda db=None: fake)

        @contextlib.contextmanager
        def fake_session():
            yield None

        import db.connection.session as session_mod

        monkeypatch.setattr(session_mod, "SessionLocal", fake_session)
        rendered = "".join(metrics_mod._queue_lines())
        assert 'cryptoscan_scan_queue_depth 7' in rendered
        assert 'cryptoscan_scan_queue_limit 1000' in rendered
        assert 'cryptoscan_scan_queue_refused_total 3' in rendered
        assert 'cryptoscan_scan_queue_failed_total 1' in rendered

    def test_queue_failure_never_silences_the_metrics_surface(self, monkeypatch):
        import db.connection.session as session_mod

        def boom():
            raise RuntimeError("db down")

        monkeypatch.setattr(session_mod, "SessionLocal", boom)
        assert metrics_mod._queue_lines() == []  # degraded, not dead


# ---------------------------------------------------------------------------
# The queue-depth signal must have CONSUMERS, not just a producer: an
# autoscaler that reads backlog, and adapter wiring for the plain-HPA form.
# ---------------------------------------------------------------------------


class TestQueueSignalConsumers:
    KEDA = ROOT / "deploy" / "stack" / "k8s" / "26-worker-keda.yaml"
    ADAPTER = ROOT / "deploy" / "stack" / "prometheus" / "adapter-snippet.yaml"
    HPA = ROOT / "deploy" / "stack" / "k8s" / "25-worker-hpa.yaml"

    def test_keda_scales_the_worker_on_queue_depth(self):
        text = self.KEDA.read_text()
        assert "kind: ScaledObject" in text
        assert "cryptoscan_scan_queue_depth" in text
        assert "name: cryptoscan-worker" in text
        assert 'activationThreshold: "1"' in text  # any backlog wakes it
        # bounds are policy: floor is never zero, ceiling is explicit
        assert "minReplicas: 2" in text and "maxReplicas: 12" in text

    def test_one_controller_per_deployment_never_both(self):
        keda = self.KEDA.read_text()
        hpa = self.HPA.read_text()
        assert "ONE of the two" in hpa and "never both" in keda.lower() or "never both" in hpa
        # the chart renders exactly one form: the CPU HPA gate excludes keda
        deploy = (ROOT / "k8s" / "helm" / "cryptoscan" / "templates" / "worker-deployment.yaml").read_text()
        assert "not .Values.worker.autoscaling.keda.enabled" in deploy

    def test_adapter_wiring_exists_for_the_plain_hpa_form(self):
        text = self.ADAPTER.read_text()
        assert "cryptoscan_scan_queue_depth" in text
        assert "cryptoscan_scan_queue_refused_total" in text
        assert "prometheus-adapter" in text.lower()

    def test_chart_keda_form_is_gated_off_by_default(self):
        values = (ROOT / "k8s" / "helm" / "cryptoscan" / "values.yaml").read_text()
        assert "keda:" in values and "enabled: false" in values
        tmpl = (ROOT / "k8s" / "helm" / "cryptoscan" / "templates" / "worker-keda.yaml").read_text()
        assert "kind: ScaledObject" in tmpl
        assert ".Values.worker.autoscaling.keda.enabled" in tmpl
        assert "cryptoscan_scan_queue_depth" in tmpl


# ---------------------------------------------------------------------------
# Scheduled verifiers: integrity and recovery are standing signals, not
# things discovered by happenstance.
# ---------------------------------------------------------------------------


class TestScheduledVerifiers:
    SYSTEMD = ROOT / "deploy" / "systemd"

    def test_audit_verification_is_scheduled_and_fail_loud(self):
        service = (self.SYSTEMD / "cryptoscan-audit-verify.service").read_text()
        timer = (self.SYSTEMD / "cryptoscan-audit-verify.timer").read_text()
        assert "scripts/audit_verify.py" in service
        assert "Type=oneshot" in service
        assert "OnCalendar=" in timer          # daily floor
        assert "Persistent=true" in timer
        # the README tells the operator what a failure means
        readme = (self.SYSTEMD / "README.md").read_text()
        assert "TAMPERED" in readme

    def test_audit_verify_exit_codes_are_the_unit_health(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "audit_verify", ROOT / "scripts" / "audit_verify.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        ok, _ = mod.evaluate({"status": "OK"})
        bad, report = mod.evaluate({"status": "TAMPERED"})
        unknown, _ = mod.evaluate({})
        assert (ok, bad, unknown) == (0, 1, 2)
        assert report["ok"] is False and "incident" in report["note"]

    def test_restore_drill_is_scheduled_and_records_evidence(self):
        service = (self.SYSTEMD / "cryptoscan-restore-drill.service").read_text()
        timer = (self.SYSTEMD / "cryptoscan-restore-drill.timer").read_text()
        assert "scripts/backup_drill.py" in service
        assert "--record-evidence" in service
        assert "OnCalendar=Sun" in timer       # weekly
        assert "Persistent=true" in timer

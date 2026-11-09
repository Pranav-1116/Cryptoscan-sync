"""The local launcher must not turn missing credentials into a fake estate."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_local_stack.sh"


def _env(tmp_path):
    env = os.environ.copy()
    for key in ("LOCAL_DB_PASS_FILE", "LOCAL_APP_PASS_FILE", "LOCAL_SECRET_KEY", "LOCAL_WEBHOOK_SECRET",
                "LOCAL_EVIDENCE_REQUIRED", "LOCAL_TWIN_OBJECT_TIER",
                "SBOM_S3_ENDPOINT", "SBOM_S3_BUCKET",
                "SBOM_S3_ACCESS_KEY_FILE", "SBOM_S3_SECRET_KEY_FILE"):
        env.pop(key, None)
    env["LOCAL_RUN_DIR"] = str(tmp_path / "never-created")
    # This test proves refusal for an explicitly unconfigured install. The
    # operator's private .env must never turn a negative test into a real up.
    env["LOCAL_ENV_AUTOLOAD"] = "0"
    env.pop("LOCAL_ENV_FILE", None)
    return env


def test_up_without_private_credentials_refuses_before_touching_the_estate(tmp_path):
    result = subprocess.run(["bash", str(SCRIPT), "up"], cwd=ROOT, env=_env(tmp_path),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "LOCAL_DB_PASS_FILE" in result.stderr
    assert not (tmp_path / "never-created").exists()


def test_required_minio_evidence_does_not_silently_fall_back_to_disk(tmp_path):
    password_file = tmp_path / "test-only-password"
    password_file.write_text("test-only-not-a-real-password")
    password_file.chmod(0o600)
    app_file = tmp_path / "test-only-app-password"
    app_file.write_text("test-only-not-a-real-app-password")
    app_file.chmod(0o600)
    env = _env(tmp_path)
    env.update({"LOCAL_DB_PASS_FILE": str(password_file), "LOCAL_APP_PASS_FILE": str(app_file),
                "LOCAL_SECRET_KEY": "s" * 40, "LOCAL_WEBHOOK_SECRET": "w" * 40})
    result = subprocess.run(["bash", str(SCRIPT), "up"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "SBOM_S3_ENDPOINT" in result.stderr
    assert not (tmp_path / "never-created").exists()


def test_twin_object_tier_cannot_be_enabled_without_bank_s3(tmp_path):
    password_file = tmp_path / "test-only-password"
    password_file.write_text("test-only-not-a-real-password")
    password_file.chmod(0o600)
    app_file = tmp_path / "test-only-app-password"
    app_file.write_text("test-only-not-a-real-app-password")
    app_file.chmod(0o600)
    env = _env(tmp_path)
    env.update({"LOCAL_DB_PASS_FILE": str(password_file), "LOCAL_APP_PASS_FILE": str(app_file),
                "LOCAL_SECRET_KEY": "s" * 40, "LOCAL_WEBHOOK_SECRET": "w" * 40,
                "LOCAL_EVIDENCE_REQUIRED": "0", "LOCAL_TWIN_OBJECT_TIER": "1"})
    result = subprocess.run(["bash", str(SCRIPT), "up"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "requires the bank-owned S3 evidence backend" in result.stderr
    assert not (tmp_path / "never-created").exists()


def test_private_env_is_loaded_for_a_plain_status_invocation(tmp_path):
    private = tmp_path / "local.env"
    private.write_text("LOCAL_API_PORT=18981\nLOCAL_UI_PORT=18982\n")
    private.chmod(0o600)
    env = _env(tmp_path)
    env.update({"LOCAL_ENV_AUTOLOAD": "1", "LOCAL_ENV_FILE": str(private)})
    result = subprocess.run(["bash", str(SCRIPT), "status"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "127.0.0.1:18981" in result.stdout
    assert "127.0.0.1:18982" in result.stdout


def test_shared_or_symlinked_env_is_refused_before_launch(tmp_path):
    private = tmp_path / "local.env"
    private.write_text("LOCAL_API_PORT=18981\n")
    private.chmod(0o644)
    env = _env(tmp_path)
    env.update({"LOCAL_ENV_AUTOLOAD": "1", "LOCAL_ENV_FILE": str(private)})
    result = subprocess.run(["bash", str(SCRIPT), "status"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and "mode 0600" in result.stderr
    private.chmod(0o600)
    link = tmp_path / "link.env"
    link.symlink_to(private)
    env["LOCAL_ENV_FILE"] = str(link)
    result = subprocess.run(["bash", str(SCRIPT), "status"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and "not a symlink" in result.stderr


def test_binding_refuses_another_estate_before_starting_containers(tmp_path):
    run_dir = tmp_path / "never-created"
    run_dir.mkdir(mode=0o700)
    (run_dir / "core-estate.binding").write_text("v1|another-estate\n")
    passwords = []
    for name in ("db-password", "app-password"):
        path = tmp_path / name
        path.write_text("only-a-test-credential\n")
        path.chmod(0o600)
        passwords.append(path)
    env = _env(tmp_path)
    env.update({"LOCAL_DB_PASS_FILE": str(passwords[0]),
                "LOCAL_APP_PASS_FILE": str(passwords[1]),
                "LOCAL_SECRET_KEY": "s" * 40,
                "LOCAL_WEBHOOK_SECRET": "w" * 40,
                "LOCAL_EVIDENCE_REQUIRED": "0"})
    result = subprocess.run(["bash", str(SCRIPT), "up"], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "bound to a different estate" in result.stderr
    assert "postgres starting" not in result.stderr


def test_local_gateway_template_stays_loopback_and_routes_real_api_and_console():
    template = (ROOT / ".docker" / "nginx" / "nginx.local.template.conf").read_text()
    assert "listen 127.0.0.1:55920" in template
    assert "server 127.0.0.1:@API_PORT@" in template
    assert "server 127.0.0.1:@UI_PORT@" in template
    assert "location /api/" in template and "location / {" in template
    assert "ssl_certificate" not in template  # local HTTP is not a bank TLS claim


def test_tools_command_distinguishes_requested_services_from_installed_wiring(tmp_path):
    result = subprocess.run(["bash", str(SCRIPT), "tools"], cwd=ROOT, env=_env(tmp_path),
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0
    for tool in ("PostgreSQL", "Neo4j", "Redis", "Celery", "Kafka", "MinIO",
                 "OpenSearch", "Prometheus", "Grafana", "OpenTelemetry", "Vault",
                 "OIDC/SAML/LDAP", "NGINX", "Kubernetes", "Docker", "Pydantic", "Alembic"):
        assert tool in result.stdout
    assert "existing Redis worker + SQL outbox is not Celery" in result.stdout
    assert "no broker or committed consumer wiring" in result.stdout

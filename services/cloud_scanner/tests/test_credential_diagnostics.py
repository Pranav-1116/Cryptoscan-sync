"""Credential-chain diagnostics: source detection, hygiene warnings, no secrets."""

from __future__ import annotations

from pathlib import Path

from cloud_scanner.auth.diagnostics import credential_status


def test_aws_env_static_keys_detected_and_warned(tmp_path: Path):
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLEKEYID",
        "AWS_SECRET_ACCESS_KEY": "super-secret-value",
        "AWS_DEFAULT_REGION": "eu-central-1",
    }
    status = credential_status(env, home=tmp_path)
    aws = next(row for row in status["providers"] if row["provider"] == "aws")
    assert aws["effective_source"] == "env-static-keys"
    assert aws["region_hint"] == "eu-central-1"
    assert any("static keys" in warning for warning in aws["warnings"])
    assert "aws" in status["configured"]
    rendered = repr(status)
    assert "AKIAEXAMPLEKEYID" not in rendered and "super-secret-value" not in rendered


def test_aws_workload_identity_and_ecs_beat_static_ordering(tmp_path: Path):
    env = {
        "AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/secrets/tokn",
        "AWS_ROLE_ARN": "arn:aws:iam::111:role/scanner",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/creds",
        "AWS_ACCESS_KEY_ID": "AKIA1",
        "AWS_SECRET_ACCESS_KEY": "s",
    }
    aws = credential_status(env, home=tmp_path)["providers"][0]
    sources = [row["source"] for row in aws["detected"]]
    # documented SDK order: env static keys first, then container, then web identity
    assert sources[:3] == ["env-static-keys", "ecs-container-role", "web-identity-irsa"]
    assert aws["effective_source"] == "env-static-keys"
    assert aws["cross_account_role_arn"] == "arn:aws:iam::111:role/scanner"


def test_aws_shared_credentials_file_profiles(tmp_path: Path):
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text("[default]\naws_access_key_id = x\n\n[bank-prod]\nregion = eu\n")
    env = {"AWS_PROFILE": "bank-prod"}
    aws = credential_status(env, home=tmp_path)["providers"][0]
    assert aws["effective_source"] == "shared-credentials-file"  # the credential material
    assert any(row["source"] == "profile-selected" for row in aws["detected"])  # the selector
    shared = next(row for row in aws["detected"] if row["source"] == "shared-credentials-file")
    assert "bank-prod" in shared["detail"] and "default" in shared["detail"]
    assert "aws_access_key_id = x" not in shared["detail"]  # file contents never leaked


def test_gcp_service_account_and_missing_file(tmp_path: Path):
    ok = credential_status({"GOOGLE_APPLICATION_CREDENTIALS": "/etc/sa.json", "GOOGLE_CLOUD_PROJECT": "bank-prod"}, home=tmp_path)
    gcp = ok["providers"][1]
    assert gcp["effective_source"] == "service-account-file"
    assert gcp["project_hint"] == "bank-prod"
    missing = credential_status({"GOOGLE_APPLICATION_CREDENTIALS": "/nope/absent.json"}, home=tmp_path)["providers"][1]
    assert "FILE MISSING" in missing["detected"][0]["detail"]


def test_gcp_adc_and_metadata_fallback(tmp_path: Path):
    (tmp_path / ".config" / "gcloud").mkdir(parents=True)
    (tmp_path / ".config" / "gcloud" / "application_default_credentials.json").write_text("{}")
    gcp = credential_status({}, home=tmp_path)["providers"][1]
    assert gcp["effective_source"] == "gcloud-adc"
    bare = credential_status({}, home=tmp_path / "empty")["providers"][1]
    assert bare["effective_source"] == "metadata-server"
    assert any("not probed" in row["detail"] for row in bare["detected"])


def test_azure_service_principal_kinds_and_managed_identity(tmp_path: Path):
    sp = credential_status(
        {"AZURE_CLIENT_ID": "cid", "AZURE_TENANT_ID": "tid", "AZURE_CLIENT_SECRET": "shh", "AZURE_SUBSCRIPTION_ID": "sub-1"},
        home=tmp_path,
    )["providers"][2]
    assert sp["effective_source"] == "env-service-principal"
    assert "client-secret" in sp["detected"][0]["detail"]
    assert sp["subscription_hint"] == "sub-1"
    assert any("client secret" in w for w in sp["warnings"])
    assert "shh" not in repr(sp)
    wi = credential_status({"AZURE_CLIENT_ID": "cid", "AZURE_TENANT_ID": "tid"}, home=tmp_path)["providers"][2]
    assert "workload identity" in wi["detected"][0]["detail"]
    app_service = credential_status({"IDENTITY_ENDPOINT": "http://172.x/.info"}, home=tmp_path)["providers"][2]
    assert app_service["effective_source"] == "managed-identity-endpoint"


def test_clean_environment_reports_fallbacks_honestly(tmp_path: Path):
    status = credential_status({}, home=tmp_path / "nothing")
    assert status["configured"] == []
    for row in status["providers"]:
        assert row["effective_source"] in {"instance-metadata-imds", "metadata-server", "imds-managed-identity"}
        assert any("not probed" in item["detail"] for item in row["detected"])
    assert any("no network calls" in note for note in status["notes"])


def test_scrub_redacts_value_like_keys():
    from cloud_scanner.auth.diagnostics import _scrub

    dirty = {"aws_secret_access_key": "leak", "nested": {"client_secret": "leak"}, "ok": True, "list": [{"token": "leak"}]}
    clean = _scrub(dirty)
    assert clean["aws_secret_access_key"] == "[redacted]"
    assert clean["nested"]["client_secret"] == "[redacted]"
    assert clean["list"][0]["token"] == "[redacted]"
    assert "leak" not in repr(clean)

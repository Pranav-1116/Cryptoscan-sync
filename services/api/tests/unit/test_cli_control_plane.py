"""``cryptoscan`` as a control-plane client — the CLI must not scan, guess or lie.

Four properties are under test, and they are the product's, not the code's:

* **the CLI never collects.** ``scan --dry-run`` fetches the platform's plan and issues no
  other request; ``scan --target`` refuses before submitting when it cannot state the
  target revision; every submission is a POST to a named endpoint, and the output says so;
* **a missing capability is a refusal, not an invention.** ``evidence show``, ``evidence
  verify``, ``scope diff`` and ``explain finding`` name the closest endpoints that exist
  and exit 3, because inventing a route or an answer is the failure this product exists to
  avoid;
* **failure is not success.** A 401 exits 1 with the login hint, a 5xx exits 2 (incomplete)
  and says not to read it as an empty estate;
* **a probe with no verdict is NOT_OBSERVED.** ``doctor`` must not turn a 200 with no
  ``status`` field into a green tick.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest

from api import cli_remote
from api.cli import main

BASE = "https://control-plane.bank.internal"


class FakeControlPlane:
    """A transport that answers from a path→payload map and records every request."""

    def __init__(self, routes: dict[tuple[str, str], tuple[int, object]] | None = None) -> None:
        self.routes = routes or {}
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(self, method, url, headers, body, context, timeout):  # noqa: ANN001
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        self.calls.append((method, path + (f"?{parsed.query}" if parsed.query else ""), dict(headers), body))
        for (want_method, want_path), (status, payload) in self.routes.items():
            if method == want_method and path == want_path:
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return cli_remote.Response(status, {"content-type": "application/json"}, data)
        return cli_remote.Response(404, {}, json.dumps({"detail": "no such route in this fake"}).encode())

    @property
    def paths(self) -> list[str]:
        return [call[1] for call in self.calls]


@pytest.fixture
def env(tmp_path, monkeypatch):
    """An isolated config file and server, so no test can touch ~/.config or a socket."""
    config = tmp_path / "config.json"
    monkeypatch.setattr(cli_remote, "DEFAULT_CONFIG_PATH", config)
    monkeypatch.setenv("CRYPTOSCAN_SERVER", BASE)
    monkeypatch.setenv("CRYPTOSCAN_TOKEN", "session-token")
    monkeypatch.delenv("CRYPTOSCAN_API_KEY", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_PASSWORD", raising=False)
    return {"config": config, "tmp": tmp_path}


def run(monkeypatch, transport: FakeControlPlane, *argv: str) -> int:
    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    return main(list(argv))


# --- refusals before any request -------------------------------------------------------


def test_an_unconfigured_client_refuses_before_opening_a_connection(capsys, monkeypatch, env):
    monkeypatch.delenv("CRYPTOSCAN_SERVER")
    monkeypatch.delenv("CRYPTOSCAN_TOKEN")
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "status") == 3
    assert transport.calls == [], "the CLI probed a server it had no address for"
    err = capsys.readouterr().err
    assert "REFUSED" in err and "no server configured" in err
    assert "cryptoscan login" in err


def test_status_without_credentials_names_the_credential_problem(capsys, monkeypatch, env):
    monkeypatch.delenv("CRYPTOSCAN_TOKEN")
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "status") == 3
    assert transport.calls == []
    assert "no credential configured" in capsys.readouterr().err


# --- status / doctor -------------------------------------------------------------------


def test_status_reads_three_named_endpoints_and_prints_identity(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/healthz"): (200, {"status": "ok"}),
        ("GET", "/api/v1/readiness/summary"): (200, {"status": "READY"}),
        ("GET", "/api/v1/auth/me"): (200, {"username": "ops.bank", "roles": ["auditor"], "tenant_id": "a"}),
    })
    assert run(monkeypatch, transport, "status") == 0
    out = capsys.readouterr().out
    assert "ops.bank" in out and "auditor" in out
    assert "source: GET /api/v1/healthz, /readiness/summary, /auth/me" in out
    assert transport.paths == ["/api/v1/healthz", "/api/v1/readiness/summary", "/api/v1/auth/me"]


def test_doctor_is_ready_only_when_every_probe_answers(capsys, monkeypatch, env):
    routes = {("GET", path): (200, {"status": "ok"}) for _, path in cli_remote.CHECKS}
    routes[("GET", "/api/v1/auth/me")] = (200, {"username": "ops.bank"})
    assert run(monkeypatch, FakeControlPlane(routes), "doctor") == 0
    out = capsys.readouterr().out
    assert "Result: READY" in out
    assert "does not mean a scan has run" in out


def test_doctor_calls_a_silent_probe_not_observed_instead_of_a_pass(capsys, monkeypatch, env):
    routes = {("GET", path): (200, {"status": "ok"}) for _, path in cli_remote.CHECKS}
    routes[("GET", "/api/v1/auth/me")] = (200, {"username": "ops.bank"})
    routes[("GET", "/api/v1/graph/health")] = (200, {"detail": "no verdict here"})
    assert run(monkeypatch, FakeControlPlane(routes), "doctor") == 0
    out = capsys.readouterr().out
    assert "NOT_OBSERVED" in out
    assert "Result: READY WITH WARNINGS" in out


def test_doctor_is_not_ready_when_a_dependency_fails(capsys, monkeypatch, env):
    routes = {("GET", path): (200, {"status": "ok"}) for _, path in cli_remote.CHECKS}
    routes[("GET", "/api/v1/auth/me")] = (200, {"username": "ops.bank"})
    routes[("GET", "/api/v1/healthz/dependencies")] = (503, {"detail": "database unreachable"})
    assert run(monkeypatch, FakeControlPlane(routes), "doctor") == 2
    out = capsys.readouterr().out
    assert "Result: NOT READY" in out


def test_doctor_refuses_when_there_is_no_client(capsys, monkeypatch, env):
    monkeypatch.delenv("CRYPTOSCAN_SERVER")
    assert run(monkeypatch, FakeControlPlane(), "doctor") == 3
    assert "client configuration" in capsys.readouterr().out


# --- login / logout --------------------------------------------------------------------


def test_login_stores_a_private_session_and_never_prints_it(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/auth/login"): (200, {
            "message": "ok", "username": "ops.bank", "roles": ["auditor"],
            "token": "session-abc", "session_expires_at": "2026-10-28T12:00:00Z",
        }),
    })
    code = run(monkeypatch, transport, "login", "--username", "ops.bank",
               "--password", "correct-horse")
    assert code == 0
    out = capsys.readouterr().out
    assert "session-abc" not in out, "the CLI echoed the session token"
    saved = json.loads(Path(env["config"]).read_text())
    assert saved["token"] == "session-abc"
    assert (Path(env["config"]).stat().st_mode & 0o777) == 0o600
    assert "session token, not a permanent key" in out
    assert json.loads(transport.calls[0][3]) == {"username": "ops.bank", "password": "correct-horse"}


def test_login_without_the_second_factor_stops_instead_of_saving_a_challenge(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/auth/login"): (200, {
            "message": "mfa required", "username": "ops.bank", "roles": [],
            "token": "", "session_expires_at": "2026-10-28T12:00:00Z",
            "mfa_required": True, "mfa_token": "challenge-1",
        }),
    })
    code = run(monkeypatch, transport, "login", "--username", "ops.bank", "--password", "pw")
    assert code == 3
    assert "--mfa-code" in capsys.readouterr().err
    assert not Path(env["config"]).exists(), "a challenge token was stored as if it were a session"


def test_login_with_the_second_factor_completes_the_session(monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/auth/login"): (200, {
            "message": "mfa required", "username": "ops.bank", "roles": [],
            "token": "", "session_expires_at": "2026-10-28T12:00:00Z",
            "mfa_required": True, "mfa_token": "challenge-1",
        }),
        ("POST", "/api/v1/auth/login/mfa"): (200, {
            "message": "ok", "username": "ops.bank", "roles": ["auditor"],
            "token": "session-abc", "session_expires_at": "2026-10-28T12:00:00Z",
        }),
    })
    assert run(monkeypatch, transport, "login", "--username", "ops.bank", "--password", "pw",
               "--mfa-code", "123456") == 0
    assert json.loads(Path(env["config"]).read_text())["token"] == "session-abc"


def test_logout_revokes_then_clears_the_stored_token(capsys, monkeypatch, env):
    cli_remote.save_config(cli_remote.Config(server=BASE, token="session-abc"))
    transport = FakeControlPlane({("POST", "/api/v1/auth/logout"): (200, {"message": "bye"})})
    assert run(monkeypatch, transport, "logout") == 0
    assert cli_remote.load_config().token is None
    assert "revoked_by_server" in capsys.readouterr().out


# --- targets ---------------------------------------------------------------------------


def test_target_register_refuses_without_the_fields_that_are_an_authorisation(capsys, monkeypatch, env):
    transport = FakeControlPlane()
    code = run(monkeypatch, transport, "target", "register", "--target-key", "t1",
               "--system-id", "payments")
    assert code == 3
    err = capsys.readouterr().err
    assert "explicit fields" in err
    assert "no default for these" in err
    assert transport.calls == [], "an incomplete authorisation still reached the control plane"


def test_target_register_posts_exactly_the_authorisation_the_operator_wrote(monkeypatch, env):
    transport = FakeControlPlane({("POST", "/api/v1/collection/targets"): (201, {"target_key": "pay-01"})})
    code = run(monkeypatch, transport, "target", "register",
               "--target-key", "pay-01", "--system-id", "payments", "--owner", "crypto-team",
               "--environment", "production", "--collection-method", "ssh-readonly",
               "--address", "10.0.0.5", "--not-before", "2026-10-28T00:00:00Z",
               "--allowed-operation", "READ_PACKAGES", "--allowed-operation", "READ_TLS_CONFIG")
    assert code == 0
    body = json.loads(transport.calls[0][3])
    assert body["allowed_operations"] == ["READ_PACKAGES", "READ_TLS_CONFIG"]
    assert body["not_before"] == "2026-10-28T00:00:00Z"
    assert "credential_ref" not in body
    assert transport.paths == ["/api/v1/collection/targets"]


def test_target_list_renders_the_listing_wrapper_it_was_given(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/collection/targets"): (200, {"items": [
            {"target_key": "pay-01", "system_id": "payments", "environment": "production",
             "collection_method": "ssh-readonly", "read_only": True, "status": "AUTHORIZED"},
        ]}),
    })
    assert run(monkeypatch, transport, "target", "list") == 0
    out = capsys.readouterr().out
    assert "pay-01" in out and "AUTHORIZED" in out and "YES" in out


# --- scan: the CLI must not collect ----------------------------------------------------


def test_dry_run_reads_the_plan_and_issues_nothing_else(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/plan"): (200, {
            "estate": "default",
            "planes": [{"plane": "STATIC", "status": "READY"}, {"plane": "HSM", "status": "NOT_CONFIGURED"}],
        }),
    })
    assert run(monkeypatch, transport, "scan", "--dry-run") == 0
    out = capsys.readouterr().out
    assert transport.calls[0][0] == "GET"
    assert all(method == "GET" for method, *_ in transport.calls), "a dry run issued a write"
    assert "DRY RUN — nothing was collected" in out
    assert "HSM" in out


def test_scan_target_without_a_revision_refuses_before_submitting(capsys, monkeypatch, env):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "scan", "--target", "pay-01") == 3
    assert transport.calls == []
    assert "expected target revision" in capsys.readouterr().err


def test_scan_system_submits_one_job_and_names_the_endpoint(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/systems/payments/scan"): (202, {"scan_id": "scan-77", "status": "QUEUED"}),
    })
    assert run(monkeypatch, transport, "scan", "--system", "payments") == 0
    out = capsys.readouterr().out
    assert "scan-77" in out
    assert "source: POST /api/v1/systems/payments/scan" in out
    assert "collectors run inside the bank" in out


def test_scan_manifest_reports_fields_the_api_cannot_honour(capsys, monkeypatch, env):
    manifest = Path(env["tmp"]) / "payments.json"
    manifest.write_text(json.dumps({
        "scope": {"name": "payments-production"},
        "collectors": {"static": True, "runtime": True},
        "policy": {"profile": "banking"},
    }))
    transport = FakeControlPlane({
        ("POST", "/api/v1/estate/evidence/scan"): (202, {"job_id": "job-1"}),
    })
    assert run(monkeypatch, transport, "scan", "--manifest", str(manifest)) == 0
    err = capsys.readouterr().err
    assert "policy" in err and "NOT sent" in err
    body = json.loads(transport.calls[0][3])
    assert body["scope"] == "payments-production"
    assert body["planes"] == ["STATIC", "RUNTIME"]


def test_scan_remote_mode_is_selected_by_flags_not_by_silence(monkeypatch, env):
    """Without a control-plane flag the command keeps its in-process behaviour."""
    from api import cli

    args = cli._build_parser().parse_args(["scan"])
    assert cli._remote_scan_requested(args) is False
    args = cli._build_parser().parse_args(["scan", "--dry-run"])
    assert cli._remote_scan_requested(args) is True


# --- evidence / bom / pqc / scope / explain --------------------------------------------


@pytest.mark.parametrize("argv,reason", [
    (("scope", "diff"), "no scope-diff endpoint"),
])
def test_capabilities_that_do_not_exist_are_refused_with_the_closest_route(
        capsys, monkeypatch, env, argv, reason):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, *argv) == 3
    err = capsys.readouterr().err
    assert reason in err
    assert "closest existing endpoint" in err
    assert transport.calls == [], "a refused command still called the control plane"


def test_bom_rejects_an_unknown_projection_before_asking(monkeypatch, env):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "bom", "XBOM") == 3
    assert transport.calls == []


def test_bom_reads_one_projection_and_states_what_empty_means(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/boms"): (200, {"run_id": 12, "CBOM": {"schema": "x", "items": []}}),
    })
    assert run(monkeypatch, transport, "bom", "cbom") == 0
    out = capsys.readouterr().out
    assert "GET /api/v1/estate/evidence/boms?bom=CBOM" in out.replace("source: ", "")
    assert "nothing was observed" in out


def test_explain_asset_asks_with_the_fact_type_the_route_requires(monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/why/payments-api"): (200, {
            "subject": "payments-api", "evidence": ["EVID-1"], "reason": "TLS 1.2 observed",
            "policy": "BANK-TLS-003", "confidence": "HIGH",
        }),
    })
    assert run(monkeypatch, transport, "explain", "asset", "payments-api",
               "--fact-type", "CRYPTO_ALGORITHM") == 0
    path = transport.paths[0]
    assert path.startswith("/api/v1/estate/evidence/why/payments-api")
    assert "fact_type=CRYPTO_ALGORITHM" in path


def test_pqc_blockers_reports_the_missing_field_instead_of_failing_silently(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/pqc"): (200, {"run_id": 3, "layers": {"TLS": {"classical": 2}}}),
    })
    assert run(monkeypatch, transport, "pqc", "blockers") == 2
    out = capsys.readouterr()
    assert "no `blockers` field" in out.err
    assert "TLS" in out.out


# --- jobs ------------------------------------------------------------------------------


def test_jobs_cancel_uses_the_collection_cancel_endpoint(monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/collection/jobs/job-9/cancel"): (200, {"status": "CANCELLED"}),
    })
    assert run(monkeypatch, transport, "jobs", "cancel", "job-9") == 0
    assert transport.paths == ["/api/v1/collection/jobs/job-9/cancel"]


def test_jobs_watch_stops_at_a_terminal_state_and_reports_success(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/jobs/job-9"): (200, {"status": "COMPLETED"})})
    monkeypatch.setattr(cli_remote.time, "sleep", lambda _s: None)
    assert run(monkeypatch, transport, "jobs", "watch", "job-9", "--interval", "0") == 0
    assert "COMPLETED" in capsys.readouterr().out


def test_jobs_watch_does_not_call_a_timeout_a_success(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/jobs/job-9"): (200, {"status": "RUNNING"})})
    monkeypatch.setattr(cli_remote.time, "sleep", lambda _s: None)
    monkeypatch.setattr(cli_remote.time, "monotonic", _monotonic_after(0.0, 5.0))
    assert run(monkeypatch, transport, "jobs", "watch", "job-9", "--timeout", "1") == 2
    assert "not treating that as success" in capsys.readouterr().err


def _monotonic_after(*values: float):
    """A monotonic clock that advances through ``values`` then holds the last one."""
    state = {"i": 0}

    def clock() -> float:
        index = min(state["i"], len(values) - 1)
        state["i"] += 1
        return values[index]

    return clock


# --- failure is not success ------------------------------------------------------------


def test_a_401_exits_nonzero_with_the_login_hint(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/jobs"): (401, {"detail": "Invalid token"})})
    assert run(monkeypatch, transport, "jobs", "list") == 1
    err = capsys.readouterr().err
    assert "HTTP 401" in err and "cryptoscan login" in err


def test_a_500_is_incomplete_not_an_empty_estate(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/estate/evidence/pqc"): (500, {"detail": "boom"})})
    assert run(monkeypatch, transport, "pqc", "status") == 2
    err = capsys.readouterr().err
    assert "do not treat it as an empty result" in err


# --- report and installation integrity --------------------------------------------------


def test_report_streams_the_body_to_disk_and_reports_its_hash(capsys, monkeypatch, env):
    pdf = b"%PDF-1.4 fake"
    transport = FakeControlPlane({("GET", "/api/v1/scans/scan-77/report.pdf"): (200, pdf)})
    out_path = Path(env["tmp"]) / "report.pdf"
    assert run(monkeypatch, transport, "report", "generate", "--scan", "scan-77",
               "--format", "pdf", "--output", str(out_path)) == 0
    assert out_path.read_bytes() == pdf
    out = capsys.readouterr().out
    assert "sha256" in out
    assert "does not check report contents" in out


def test_verify_installation_reports_mismatch_and_unsigned_manifest(capsys, monkeypatch, env):
    root = Path(env["tmp"]) / "install"
    root.mkdir()
    (root / "cli.py").write_text("print('hi')\n")
    manifest = Path(env["tmp"]) / "manifest.json"
    manifest.write_text(json.dumps({"files": {"cli.py": "0" * 64}}))
    assert run(monkeypatch, FakeControlPlane(), "verify-installation",
               "--manifest", str(manifest), "--root", str(root)) == 2
    out = capsys.readouterr().out
    assert "mismatch" in out
    assert "MANIFEST_UNSIGNED" in out
    assert "authentic only if the key you passed" in out


def test_verify_installation_matches_when_the_hashes_do(capsys, monkeypatch, env):
    import hashlib

    root = Path(env["tmp"]) / "install2"
    root.mkdir()
    payload = b"print('hi')\n"
    (root / "cli.py").write_bytes(payload)
    manifest = Path(env["tmp"]) / "manifest2.json"
    manifest.write_text(json.dumps({"files": {"cli.py": hashlib.sha256(payload).hexdigest()}}))
    assert run(monkeypatch, FakeControlPlane(), "verify-installation",
               "--manifest", str(manifest), "--root", str(root)) == 0
    assert "MATCH" in capsys.readouterr().out


def test_verify_installation_without_a_manifest_refuses(monkeypatch, env):
    assert run(monkeypatch, FakeControlPlane(), "verify-installation",
               "--manifest", str(Path(env["tmp"]) / "absent.json")) == 3


# --- config hygiene --------------------------------------------------------------------


def test_config_permissions_are_checked_not_assumed(monkeypatch, env):
    path = cli_remote.save_config(cli_remote.Config(server=BASE, token="t"))
    assert cli_remote.config_permissions(path) == "PRIVATE"
    path.chmod(0o644)
    assert cli_remote.config_permissions(path).startswith("TOO_OPEN")


def test_both_credentials_are_sent_when_both_are_configured(monkeypatch, env):
    monkeypatch.delenv("CRYPTOSCAN_TOKEN")
    cli_remote.save_config(cli_remote.Config(server=BASE, token="session", api_key="key-1"))
    transport = FakeControlPlane({("GET", "/api/v1/jobs"): (200, {"items": []})})
    assert run(monkeypatch, transport, "jobs", "list") == 0
    headers = transport.calls[0][2]
    assert headers["Authorization"] == "Bearer session"
    assert headers["x-api-key"] == "key-1"


# --- wiring: one entry point, two modes ------------------------------------------------


def test_the_entry_point_dispatches_remote_commands(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/health"): (200, {"version": "3.4.1", "status": "ok"})})
    assert run(monkeypatch, transport, "version") == 0
    out = capsys.readouterr().out
    assert "3.4.1" in out


def test_twin_status_is_remote_and_never_opens_the_local_database(monkeypatch, env):
    """``twin status`` must not silently fall back to whatever database this host has."""
    transport = FakeControlPlane({("GET", "/api/v1/estate/evidence/twin"): (200, {"assets": 3})})

    def forbidden(*_args, **_kwargs):
        raise AssertionError("the remote twin command opened a local database session")

    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    from api import cli

    monkeypatch.setattr(cli, "_session", forbidden)
    assert cli.main(["twin", "status"]) == 0
    assert transport.paths == ["/api/v1/estate/evidence/twin"]


def test_every_remote_command_is_registered_once(monkeypatch):
    from api import cli

    for name in ("version", "status", "doctor", "login", "logout", "target", "jobs",
                 "evidence", "bom", "pqc", "scope", "explain", "report", "verify-installation"):
        assert name in cli.COMMANDS, f"{name} is not wired into the entry point"
    # the in-process commands survive the merge
    for name in ("scan", "collect", "coverage", "boms", "twin", "schedule", "tick", "serve"):
        assert name in cli.COMMANDS


# --- evidence show / verify now that the routes exist ----------------------------------


def test_evidence_show_prints_provenance_and_the_raw_reference(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/evidence/records/ev-abc"): (200, {"record": {
            "evidence_id": "ev-abc", "evidence_type": "RUNTIME_OBSERVED",
            "target": "application:payments-api", "layer": "APPLICATION",
            "collector": "linux-runtime", "collector_version": "estate-collectors/1",
            "source": "runtime", "confidence": "HIGH", "observed_at": "2026-10-28T06:20:00Z",
            "observation_count": 4, "lifecycle_state": "ACTIVE", "raw_reference": "run:42",
            "facts": {"algorithm": "AES-256-GCM"},
        }}),
    })
    assert run(monkeypatch, transport, "evidence", "show", "ev-abc") == 0
    out = capsys.readouterr().out
    assert "estate-collectors/1" in out
    assert "run:42" in out
    assert "algorithm" in out and "AES-256-GCM" in out


def test_evidence_show_says_so_when_the_raw_reference_was_not_recorded(capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/evidence/records/ev-x"): (200, {"record": {
            "evidence_id": "ev-x", "raw_reference": None, "facts": {},
        }}),
    })
    assert run(monkeypatch, transport, "evidence", "show", "ev-x") == 0
    out = capsys.readouterr().out
    assert "the raw output location was not recorded" in out
    assert "the record carries no facts" in out


@pytest.mark.parametrize("verdict,expected", [
    ("CONTENT_ADDRESS_INTACT", 0),
    ("ID_NOT_CONTENT_ADDRESSED", 2),
    ("CONTENT_ADDRESS_MISMATCH", 1),
])
def test_evidence_verify_maps_the_verdict_to_an_exit_code(capsys, monkeypatch, env, verdict, expected):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/evidence/records/ev-1/verify"): (200, {
            "evidence_id": "ev-1", "recomputed_id": "ev-2", "verdict": verdict,
            "content_addressed": verdict != "ID_NOT_CONTENT_ADDRESSED",
            "not_checked": ["collector honesty: nothing signs the observation"],
            "limits": "this is an integrity check on the stored record, not an attestation "
                      "of the observation it describes",
        }),
    })
    assert run(monkeypatch, transport, "evidence", "verify", "ev-1") == expected
    out = capsys.readouterr().out
    assert verdict in out
    assert "not an attestation" in out


# --- jobs retry / coverage -------------------------------------------------------------


def test_jobs_retry_uses_the_retry_route_and_warns_about_the_refusals(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/jobs/job-3/retry"): (202, {"id": "job-4", "status": "QUEUED"}),
    })
    assert run(monkeypatch, transport, "jobs", "retry", "job-3") == 0
    out = capsys.readouterr().out
    assert "job-4" in out
    assert "unsettled (409)" in out


def test_jobs_watch_can_print_real_surface_coverage(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/jobs/job-9"): (200, {"status": "COMPLETED"}),
        ("GET", "/api/v1/collection/jobs/job-9/coverage"): (200, {
            "surfaces": {"PACKAGES": {"state": "COLLECTED", "count": 412},
                         "TLS": {"state": "NOT_AUTHORIZED"}},
            "basis": "EXACT_AUTHORIZED_MANIFEST_INPUTS_NOT_ESTATE_INVENTORY",
        }),
    })
    monkeypatch.setattr(cli_remote.time, "sleep", lambda _s: None)
    assert run(monkeypatch, transport, "jobs", "watch", "job-9", "--coverage") == 0
    out = capsys.readouterr().out
    assert "PACKAGES" in out and "412" in out
    assert "NOT_AUTHORIZED" in out
    assert "EXACT_AUTHORIZED_MANIFEST_INPUTS_NOT_ESTATE_INVENTORY" in out


# --- ci gate ---------------------------------------------------------------------------


def _gate(decision, blocking=(), warnings=()):
    return {"decision": decision, "profile": "banking", "blocking": list(blocking),
            "warnings": list(warnings), "scan_id": "scan-1"}


def test_ci_gate_fails_the_build_on_fail_and_names_the_blocking_items(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/scans/scan-1/gate"): (200, _gate(
        "FAIL", blocking=[{"code": "WEAK_CRYPTO", "message": "3DES in payments"}]))})
    assert run(monkeypatch, transport, "ci", "gate", "--scan", "scan-1") == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "WEAK_CRYPTO" in out
    assert "not from this client" in out


def test_ci_gate_treats_warn_as_success_unless_asked_otherwise(monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/scans/scan-1/gate"): (200, _gate("WARN"))})
    assert run(monkeypatch, transport, "ci", "gate", "--scan", "scan-1") == 0
    assert run(monkeypatch, transport, "ci", "gate", "--scan", "scan-1", "--fail-on", "warn") == 2


def test_ci_gate_does_not_treat_an_unknown_decision_as_a_pass(capsys, monkeypatch, env):
    transport = FakeControlPlane({("GET", "/api/v1/scans/scan-1/gate"): (200, {"decision": "MAYBE"})})
    assert run(monkeypatch, transport, "ci", "gate", "--scan", "scan-1") == 2
    assert "does not treat as success" in capsys.readouterr().err


def test_ci_gate_can_record_the_evaluation_and_write_sarif(tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/ci/gate"): (200, {**_gate("PASS"), "recorded": True}),
        ("GET", "/api/v1/scans/scan-1/gate.sarif"): (200, {"version": "2.1.0", "runs": []}),
    })
    out_file = tmp_path / "gate.sarif"
    assert run(monkeypatch, transport, "ci", "gate", "--scan", "scan-1", "--profile", "banking",
               "--record", "--sarif", str(out_file)) == 0
    body = json.loads(transport.calls[0][3])
    assert body == {"scan_id": "scan-1", "profile": "banking", "require_baseline": False}
    assert json.loads(out_file.read_text())["version"] == "2.1.0"
    assert "recorded      True" in capsys.readouterr().out


# --- pqc impact ------------------------------------------------------------------------


def test_pqc_impact_refuses_without_a_selector(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "pqc", "impact") == 3
    assert transport.calls == []
    assert "no selector given" in capsys.readouterr().err


def test_pqc_impact_posts_the_selector_and_keeps_blast_radius_separate_from_readiness(
        capsys, monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/estate/evidence/twin/impact"): (200, {
            "run_id": 7, "affected": ["application:payments-api", "address:10.0.0.5"], "depth": 2,
            "limits": ["walk stops at depth 2"]}),
    })
    assert run(monkeypatch, transport, "pqc", "impact", "--algorithm", "RSA") == 0
    body = json.loads(transport.calls[0][3])
    assert body["algorithm"] == "RSA" and body["depth"] == 3
    out = capsys.readouterr().out
    assert "affected      2" in out
    assert "not a PQC readiness score" in out


def test_a_truncated_impact_walk_is_incomplete_not_complete(monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/estate/evidence/twin/impact"): (200, {"truncated": True, "affected": []}),
    })
    assert run(monkeypatch, transport, "pqc", "impact", "--asset", "payments-api") == 2


# --- air-gap bundles -------------------------------------------------------------------


def _bundle_routes():
    return {
        ("GET", "/api/v1/estate/evidence/evidence/records"): (200, {"records": [{"evidence_id": "ev-1"}]}),
        ("GET", "/api/v1/estate/evidence/twin/snapshot"): (200, {"assets": 2}),
        ("GET", "/api/v1/estate/evidence/pqc"): (200, {"layers": {}}),
        # the six BOM projections are deliberately absent: an export must record them as
        # unavailable rather than produce a bundle that reads as a complete estate
    }


def test_bundle_export_writes_a_manifest_and_records_unavailable_projections(
        tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane(_bundle_routes())
    out = tmp_path / "bundle"
    code = run(monkeypatch, transport, "bundle", "export", "--out", str(out))
    assert code == 2, "missing BOM projections must not read as a complete export"
    manifest = json.loads((out / "bundle.json").read_text())
    assert "evidence.json" in manifest["files"]
    assert "boms/SBOM.json" in manifest["unavailable"]
    assert manifest["signature"] is None
    assert any("who produced them" in limit for limit in manifest["limits"])
    assert manifest["sources"]["evidence.json"].startswith("GET ")
    text = capsys.readouterr().out
    assert "unavailable" in text and "UNSIGNED" in text


def test_bundle_verify_detects_a_modified_file(tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane(_bundle_routes())
    out = tmp_path / "bundle"
    run(monkeypatch, transport, "bundle", "export", "--out", str(out))
    assert run(monkeypatch, transport, "bundle", "verify", str(out)) == 0  # nothing touched yet
    (out / "pqc.json").write_text('{"layers": {"TLS": "changed"}}')
    assert run(monkeypatch, transport, "bundle", "verify", str(out)) == 2
    text = capsys.readouterr().out
    assert "modified  pqc.json" in text
    assert "signature   UNSIGNED" in text
    assert "proves nothing on its own" in text


def test_bundle_round_trips_through_encryption(tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane(_bundle_routes())
    monkeypatch.setenv("CRYPTOSCAN_BUNDLE_PASSPHRASE", "correct horse battery staple")
    out = tmp_path / "bundle"
    run(monkeypatch, transport, "bundle", "export", "--out", str(out), "--encrypt")
    envelope = tmp_path / "bundle.cse"
    assert envelope.exists()
    raw = envelope.read_bytes()
    assert b"application:payments-api" not in raw and b"evidence_id" not in raw, "bundle is not encrypted"

    into = tmp_path / "restored"
    # 0: every file matches the manifest. The missing BOMs are recorded in the manifest's
    # `unavailable` block, not in the file verdict — those are different claims.
    assert run(monkeypatch, transport, "bundle", "import", str(envelope), "--into", str(into)) == 0
    assert (into / "bundle.json").exists()
    assert json.loads((into / "pqc.json").read_text()) == {"layers": {}}
    assert "boms/SBOM.json" in json.loads((into / "bundle.json").read_text())["unavailable"]


def test_a_wrong_bundle_passphrase_is_refused_not_partially_decrypted(tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane(_bundle_routes())
    monkeypatch.setenv("CRYPTOSCAN_BUNDLE_PASSPHRASE", "right")
    out = tmp_path / "bundle"
    run(monkeypatch, transport, "bundle", "export", "--out", str(out), "--encrypt")
    monkeypatch.setenv("CRYPTOSCAN_BUNDLE_PASSPHRASE", "wrong")
    assert run(monkeypatch, transport, "bundle", "import", str(tmp_path / "bundle.cse"),
               "--into", str(tmp_path / "nope")) == 3
    err = capsys.readouterr().err
    assert "could not be decrypted" in err
    assert "cannot tell these apart" in err


def test_export_without_a_passphrase_refuses_before_writing_an_envelope(tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane(_bundle_routes())
    monkeypatch.delenv("CRYPTOSCAN_BUNDLE_PASSPHRASE", raising=False)
    assert run(monkeypatch, transport, "bundle", "export", "--out", str(tmp_path / "b"),
               "--encrypt") == 3
    assert "no bundle passphrase" in capsys.readouterr().err
    assert not (tmp_path / "b.cse").exists()


# --- collect --submit: the boundary, made explicit ------------------------------------


def test_collect_submit_sends_work_and_collects_nothing_here(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/systems/payments/scan"): (202, {"scan_id": "scan-88", "status": "QUEUED"}),
    })
    run(monkeypatch, transport, "collect", "--submit", "--system", "payments")
    out = capsys.readouterr().out
    assert "no collection happened in this process" in out
    assert "scan-88" in out
    # the only request is the submission: nothing was negotiated from this terminal
    assert transport.paths == ["/api/v1/systems/payments/scan"]


def test_local_collection_announces_the_boundary_it_crosses(capsys):
    """The in-process path still exists; it says so rather than leaving it to the docs."""
    from api import cli

    args = cli._build_parser().parse_args(["collect"])
    assert args.submit is False, "local collection must be the explicit absence of --submit"
    cli._collect_boundary_notice()
    err = capsys.readouterr().err
    assert "collecting from THIS process" in err
    assert "--submit" in err


def test_collect_submit_requires_a_target_revision(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "collect", "--submit", "--target", "pay-01") == 3
    assert transport.calls == []
    assert "expected target revision" in capsys.readouterr().err


# --- twin remediation: the hand-off, from the terminal ---------------------------------


def _remediation_payload(**overrides):
    payload = {
        "schema": "cryptoscan.estate-remediation/1",
        "persisted": False,
        "candidates": [{
            "claim_key": "rem-abc123", "source": "CONFLICT", "status": "OPEN",
            "title": "Resolve the algorithm conflict on Payment API",
            "claim": "Payment API: algorithm has 2 currently-asserted values (AES-128, AES-256-GCM)",
            "severity": "HIGH", "not_proven": ["which of the asserted values is correct"],
            "proof": {"kind": "COVERAGE_DISPUTE", "expected": "ONE_CURRENT_VALUE",
                      "note": "proven when the record holds one CURRENT value again"},
        }],
        "count": 1, "created": 1, "refreshed": 0,
        "by_source": {"CONFLICT": 1}, "by_severity": {"HIGH": 1},
        "meaning": "each item names the observation that would close it",
        "limits": ["a work item is a record that someone must act on — this module cannot "
                   "execute a fix"],
    }
    payload.update(overrides)
    return payload


def test_twin_remediate_proposes_without_persisting_by_default(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/estate/evidence/twin/remediate"): (200, _remediation_payload()),
    })

    assert run(monkeypatch, transport, "twin", "remediate") == 0

    out = capsys.readouterr().out
    assert "nothing was written" in out, "a proposal must not look like a queue entry"
    assert "COVERAGE_DISPUTE" in out
    assert "limit: a work item is a record" in out
    assert json.loads(transport.calls[0][3]) == {"persist": False}


def test_twin_remediate_persist_asks_the_server_to_open_the_work(monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/estate/evidence/twin/remediate"): (
            200, _remediation_payload(persisted=True)),
    })

    assert run(monkeypatch, transport, "twin", "remediate", "--persist") == 0

    assert json.loads(transport.calls[0][3]) == {"persist": True}


def test_twin_remediation_lists_work_and_the_proof_it_needs(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/twin/remediation"): (200, {
            "schema": "cryptoscan.estate-remediation/1",
            "items": [{
                "claim_key": "rem-abc123", "source": "CONFLICT", "status": "OPEN",
                "severity": "HIGH", "title": "Resolve the algorithm conflict on Payment API",
                "claim": "Payment API: 2 values",
                "not_proven": ["which of the asserted values is correct"],
                "proof": {"kind": "COVERAGE_DISPUTE", "note": "one CURRENT value again"},
                "proof_evidence_id": None,
            }],
            "count": 1, "by_status": {"OPEN": 1}, "by_source": {"CONFLICT": 1},
            "limits": ["..."], "meaning": "…",
        }),
    })

    assert run(monkeypatch, transport, "twin", "remediation") == 0

    out = capsys.readouterr().out
    assert "work items    1" in out
    assert "COVERAGE_DISPUTE" in out
    assert "does not prove: which of the asserted values is correct" in out


def test_twin_reconcile_reports_a_closure_with_its_citation(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/estate/evidence/twin/remediation/reconcile"): (200, {
            "schema": "cryptoscan.estate-remediation/1",
            "checked": 2,
            "proven": [{"claim_key": "rem-abc123", "title": "Resolve the algorithm conflict",
                        "proof_observation_id": "obs-9", "proof_evidence_id": "ev-c905aae30aab218a"}],
            "still_open": [{"claim_key": "rem-def456", "reason": "2 values are still asserted"}],
            "proof_unavailable": [{"claim_key": "rem-ghi789",
                                   "reason": "the fact is no longer asserted at all"}],
            "counts": {"PROVEN": 1, "STILL_OPEN": 1, "PROOF_UNAVAILABLE": 1},
            "meaning": "…", "limits": ["..."],
        }),
    })

    assert run(monkeypatch, transport, "twin", "reconcile") == 0

    out = capsys.readouterr().out
    assert "closed by obs-9 (ev-c905aae30aab218a)" in out
    assert "NO PROOF" in out, "an unasserted fact must not be reported as a fix"


# --- a bundle that can prove who made it ------------------------------------------------


def test_a_signed_bundle_verifies_against_a_trusted_key(tmp_path, monkeypatch, env, capsys):
    from shared_models import release_signature as signing

    keys = signing.generate_keypair(tmp_path / "keys")
    transport = FakeControlPlane(_bundle_routes())
    out = tmp_path / "bundle"
    run(monkeypatch, transport, "bundle", "export", "--out", str(out),
        "--sign-key", keys["private_key"])

    assert run(monkeypatch, transport, "bundle", "verify", str(out),
               "--public-key", keys["public_key"]) == 0
    text = capsys.readouterr().out
    assert "signature   VALID" in text


def test_a_rewritten_bundle_manifest_fails_its_signature(tmp_path, monkeypatch, env, capsys):
    """The attack a hash list alone cannot stop: edit a file and fix its hash."""
    from shared_models import release_signature as signing

    keys = signing.generate_keypair(tmp_path / "keys")
    transport = FakeControlPlane(_bundle_routes())
    out = tmp_path / "bundle"
    run(monkeypatch, transport, "bundle", "export", "--out", str(out),
        "--sign-key", keys["private_key"])

    (out / "pqc.json").write_text('{"layers": {"TLS": "changed"}}')
    manifest = json.loads((out / "bundle.json").read_text())
    manifest["files"]["pqc.json"] = cli_remote._sha256_bytes((out / "pqc.json").read_bytes())
    (out / "bundle.json").write_text(json.dumps(manifest))

    assert run(monkeypatch, transport, "bundle", "verify", str(out),
               "--public-key", keys["public_key"]) == 1
    assert "signature   INVALID" in capsys.readouterr().out


def test_a_bundle_signed_with_another_key_is_a_mismatch(tmp_path, monkeypatch, env, capsys):
    from shared_models import release_signature as signing

    keys = signing.generate_keypair(tmp_path / "keys")
    other = signing.generate_keypair(tmp_path / "other")
    transport = FakeControlPlane(_bundle_routes())
    out = tmp_path / "bundle"
    run(monkeypatch, transport, "bundle", "export", "--out", str(out),
        "--sign-key", keys["private_key"])

    assert run(monkeypatch, transport, "bundle", "verify", str(out),
               "--public-key", other["public_key"]) == 1
    assert "SIGNATURE_KEY_MISMATCH" in capsys.readouterr().out


# --- explain finding: two surfaces, and the gap between them ----------------------------


def _finding_payload():
    return {
        "evidence_id": "9d1f-finding", "scan_id": "scan-4",
        "algorithm": "RSA", "key_size": 2048, "mode": "CBC", "padding": "PKCS1",
        "confidence": "HIGH", "is_hardcoded_key": False,
        "file_path": "src/payments/Crypto.java", "line_number": 88,
        "compliance_status": "NON_COMPLIANT",
        "content_hash": "a" * 64, "chain_hash": "b" * 64,
    }


def test_explain_finding_reads_the_record_and_its_chain_check(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/findings/9d1f-finding"): (200, _finding_payload()),
        ("GET", "/api/v1/findings/9d1f-finding/verify"): (200, {"verdict": "INTACT"}),
    })

    assert run(monkeypatch, transport, "explain", "finding", "9d1f-finding") == 0

    out = capsys.readouterr().out
    assert "src/payments/Crypto.java:88" in out
    assert "chain check   INTACT" in out
    assert "NOT_JOINABLE" in out, "a finding has no asset id; the twin cannot be joined by guessing"
    assert "source: GET /api/v1/findings/9d1f-finding" in out


def test_explain_finding_says_so_when_the_chain_check_is_unavailable(monkeypatch, env, capsys):
    """A 403 on /verify is not a pass, and not a crash either."""
    transport = FakeControlPlane({
        ("GET", "/api/v1/findings/9d1f-finding"): (200, _finding_payload()),
        ("GET", "/api/v1/findings/9d1f-finding/verify"): (403, {"detail": "auditor role required"}),
    })

    assert run(monkeypatch, transport, "explain", "finding", "9d1f-finding") == 0

    out = capsys.readouterr().out
    assert "chain check   UNAVAILABLE" in out
    assert "auditor role required" in out


def test_explain_finding_states_what_a_chain_check_does_not_prove(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/findings/9d1f-finding"): (200, _finding_payload()),
        ("GET", "/api/v1/findings/9d1f-finding/verify"): (200, {"verdict": "INTACT"}),
    })

    run(monkeypatch, transport, "explain", "finding", "9d1f-finding")

    out = capsys.readouterr().out
    assert "not that the detection was correct" in out


# --- ci scan: a source tree the control plane can see -----------------------------------


def test_ci_scan_posts_the_path_and_says_where_it_was_resolved(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/devsecops/sbom/scan"): (201, {
            "artifact_id": "sbom-7", "format": "cyclonedx",
            "summary": {"components": 41, "crypto_relevant": 6},
            "components": [{"name": "openssl"}]}),
    })

    assert run(monkeypatch, transport, "ci", "scan", "--path", "/srv/src/payments") == 0

    body = json.loads(transport.calls[0][3])
    assert body["kind"] == "source"
    assert body["target"] == "/srv/src/payments"
    assert body["format"] == "cyclonedx"
    out = capsys.readouterr().out
    assert "resolved on the control plane" in out
    assert "sbom-7" in out
    assert "not the directory you are standing in" in out


def test_ci_scan_gate_flag_is_incomplete_rather_than_a_silent_pass(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("POST", "/api/v1/devsecops/sbom/scan"): (201, {"artifact_id": "sbom-7"}),
    })

    assert run(monkeypatch, transport, "ci", "scan", "--path", "/srv/src", "--gate") == 2
    assert "needs a scan id" in capsys.readouterr().err


def test_ci_scan_lockfile_flags_reach_the_request(monkeypatch, env):
    transport = FakeControlPlane({
        ("POST", "/api/v1/devsecops/sbom/scan"): (201, {"artifact_id": "sbom-7"}),
    })

    run(monkeypatch, transport, "ci", "scan", "--path", "/srv/src",
        "--include-vendored", "--no-lockfiles")

    body = json.loads(transport.calls[0][3])
    assert body["include_vendored"] is True
    assert body["use_lockfiles"] is False


# -- target update / collection-job artefacts / collector catalog ---------------------


def test_target_update_puts_only_the_fields_you_named(monkeypatch, env):
    transport = FakeControlPlane({
        ("PUT", "/api/v1/collection/targets/legacy-api-02"): (200, {"identifier": "legacy-api-02"}),
    })

    assert run(monkeypatch, transport, "target", "update", "legacy-api-02",
               "--owner", "payments-platform", "--allowed-operation", "READ") == 0

    body = json.loads(transport.calls[0][3])
    assert body == {"owner": "payments-platform", "allowed_operations": ["READ"]}


def test_target_update_with_nothing_to_change_refuses(monkeypatch, env, capsys):
    transport = FakeControlPlane()

    assert run(monkeypatch, transport, "target", "update", "legacy-api-02") == 3
    assert transport.calls == []
    assert "nothing to change" in capsys.readouterr().err


def test_jobs_evidence_reads_the_collection_job_route(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/collection/jobs/job-9/evidence"): (200, {"items": [
            {"evidence_id": "ev-abc", "evidence_type": "TLS_CONFIG", "target": "hsm-prod-03"}]}),
    })

    assert run(monkeypatch, transport, "jobs", "evidence", "job-9") == 0

    assert transport.calls[0][1] == "/api/v1/collection/jobs/job-9/evidence"
    out = capsys.readouterr().out
    assert "ev-abc" in out
    assert "not proof the estate is empty" in out


def test_jobs_errors_with_no_rows_says_so_without_inventing_a_cause(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/collection/jobs/job-9/errors"): (200, {"items": []}),
    })

    assert run(monkeypatch, transport, "jobs", "errors", "job-9") == 0
    assert "no collector error was recorded" in capsys.readouterr().out


def test_collector_list_counts_qualified_collectors_rather_than_listing_capabilities(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/collection/collectors"): (200, {"collectors": [
            {"id": "offline-linux/v1", "method": "offline_host",
             "state": "DEVELOPMENT_OFFLINE_ONLY", "production_execution_qualified": False},
            {"id": "approved-tls-session/candidate-v1", "method": "network",
             "state": "OPERATOR_ACTIVE_CANDIDATE_NOT_ADMITTED", "production_execution_qualified": True},
        ]}),
    })

    assert run(monkeypatch, transport, "collector", "list") == 0
    out = capsys.readouterr().out
    assert "1 of 2 collectors are production-execution qualified" in out
    assert "still collects nothing" in out


def test_collector_show_says_the_filter_happened_client_side(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/collection/collectors"): (200, {"collectors": [
            {"id": "offline-linux/v1", "method": "offline_host",
             "state": "DEVELOPMENT_OFFLINE_ONLY", "production_execution_qualified": False},
        ]}),
    })

    assert run(monkeypatch, transport, "collector", "show", "offline-linux/v1") == 0
    assert "filtered from the catalog listing client-side" in capsys.readouterr().out


def test_collector_show_for_an_absent_id_refuses_with_the_real_route(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/collection/collectors"): (200, {"collectors": [
            {"id": "offline-linux/v1", "production_execution_qualified": False},
        ]}),
    })

    assert run(monkeypatch, transport, "collector", "show", "windows-agent/v1") == 3
    err = capsys.readouterr().err
    assert "no collector 'windows-agent/v1' in the catalog" in err
    assert "GET /api/v1/collection/collectors" in err

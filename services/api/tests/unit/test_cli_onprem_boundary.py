"""The bank operator CLI reaches the real local API without a terminal database.

This is an in-process HTTP transport test, not a claim of TLS deployment or a
qualified collector. No customer network or filesystem outside the fixture is read.
"""
from pathlib import Path
from urllib.parse import urlsplit

from fastapi.testclient import TestClient

from api import cli, cli_remote
from db.models.scan_job import ScanJob
from test_assurance_workflows import assured as assured  # noqa: F401 — real human-session fixture
from test_software_supply_chain_api import banks as banks  # noqa: F401 — assured dependency


def test_cli_preflight_against_real_bank_api_refuses_unqualified_local_run(assured, monkeypatch, capsys):
    clients, session, root = assured
    source = Path(root) / "approved-repo"
    source.mkdir()
    token = clients["bank_a"].cookies.get("cryptoscan_session")
    assert token
    http = TestClient(clients["bank_a"].app)  # no browser cookie: only the CLI's bearer token

    def transport(method, url, headers, body, _context, _timeout):
        parsed = urlsplit(url)
        response = http.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""),
                                headers=headers, content=body)
        return cli_remote.Response(response.status_code, dict(response.headers), response.content)

    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    monkeypatch.setattr(cli_remote, "DEFAULT_CONFIG_PATH", Path(root) / "no-config.json")
    monkeypatch.setenv("CRYPTOSCAN_SERVER", "https://control.bank.internal")
    monkeypatch.setenv("CRYPTOSCAN_TOKEN", token)
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("CRYPTOSCAN_API_KEY", raising=False)
    try:
        assert cli.main(["scan", "--path", str(source), "--dry-run", "--tenant", "a"]) == cli.EXIT_INCOMPLETE
        output = capsys.readouterr().out
        assert "NOT_QUALIFIED" in output and "job_created" in output
        assert session.query(ScanJob).count() == 0
        assert cli.main(["scan", "--path", str(source), "--tenant", "a"]) == cli.EXIT_INCOMPLETE
        assert session.query(ScanJob).count() == 0
    finally:
        http.close()

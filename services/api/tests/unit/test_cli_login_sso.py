"""SSO login from the operator CLI — the handoff is named, never faked.

OIDC's browser flow creates a BROWSER session; the CLI says so and takes
only an IdP-issued id_token, which the control plane verifies (never the
CLI). SAML's completed browser login displays the minted session token;
the CLI stores it only after /auth/me confirms it is live. No token is
ever accepted in process arguments.
"""

from __future__ import annotations

import io
import json
import urllib.parse

import pytest

from api import cli_remote
from api.cli import main

BASE = "https://control-plane.bank.internal"


class FakeControlPlane:
    def __init__(self, routes: dict[tuple[str, str], tuple[int, object, dict]] | None = None) -> None:
        self.routes = routes or {}
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(self, method, url, headers, body, context, timeout):  # noqa: ANN001
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        self.calls.append((method, path + (f"?{parsed.query}" if parsed.query else ""),
                           dict(headers), body))
        for (want_method, want_path), (status, payload, extra_headers) in self.routes.items():
            if method == want_method and path == want_path:
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                hdrs = {"content-type": "application/json"}
                hdrs.update(extra_headers or {})
                return cli_remote.Response(status, hdrs, data)
        return cli_remote.Response(404, {},
                                   json.dumps({"detail": "no such route in this fake"}).encode())


@pytest.fixture
def env(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    monkeypatch.setattr(cli_remote, "DEFAULT_CONFIG_PATH", config)
    monkeypatch.setenv("CRYPTOSCAN_SERVER", BASE)
    monkeypatch.delenv("CRYPTOSCAN_TOKEN", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_API_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return {"config": config, "tmp": tmp_path}


def run(monkeypatch, transport: FakeControlPlane, *argv: str) -> int:
    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    return main(list(argv))


def _stored_token(env) -> str | None:
    if not env["config"].exists():
        return None
    return (json.loads(env["config"].read_text()) or {}).get("token")


STATUS_ON_OIDC = {"oidc": {"enabled": True, "authorize_url": "/api/v1/auth/oidc/authorize"},
                  "saml_enabled": False, "ldap_enabled": False}
STATUS_ON_SAML = {"oidc": {"enabled": False, "authorize_url": None},
                  "saml_enabled": True, "ldap_enabled": False}
STATUS_OFF = {"oidc": {"enabled": False, "authorize_url": None},
              "saml_enabled": False, "ldap_enabled": False}
LOGIN_OK = {"token": "sess-oidc-1", "username": "ada", "roles": ["viewer"],
            "session_expires_at": "2026-10-17T00:00:00+00:00"}


def test_password_login_without_username_refuses_naming_the_alternative(
        monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "login", "--password-stdin") == 3
    err = capsys.readouterr().err
    assert "no username given" in err and "--sso" in err
    assert transport.calls == [], "a refusal never opens the conversation with a request"


def test_sso_refuses_honestly_when_no_provider_is_configured(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/auth/sso/status"): (200, STATUS_OFF, {})})
    assert run(monkeypatch, transport, "login", "--sso") == 3
    err = capsys.readouterr().err
    assert "no SSO provider is configured on this server" in err
    assert "GET /api/v1/auth/sso/status" in err
    assert [c[1] for c in transport.calls] == ["/api/v1/auth/sso/status"]


def test_oidc_browser_flow_names_the_handoff_and_relays_the_pasted_token(
        monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/auth/sso/status"): (200, STATUS_ON_OIDC, {}),
        ("GET", "/api/v1/auth/oidc/authorize"): (
            302, b"", {"Location": "https://idp.example/authorize?state=abc"}),
        ("POST", "/api/v1/auth/oidc"): (200, LOGIN_OK, {}),
    })
    monkeypatch.setattr("webbrowser.open", lambda url: True)
    monkeypatch.setattr("getpass.getpass", lambda prompt: "idp-issued.jwt.token")
    assert run(monkeypatch, transport, "login", "--sso") == 0
    methods = [(c[0], c[1].split("?")[0]) for c in transport.calls]
    assert methods == [("GET", "/api/v1/auth/sso/status"),
                       ("GET", "/api/v1/auth/oidc/authorize"),
                       ("POST", "/api/v1/auth/oidc")]
    relayed = json.loads(transport.calls[2][3])
    assert relayed == {"token": "idp-issued.jwt.token"}
    out = capsys.readouterr().out
    assert "https://idp.example/authorize?state=abc" in out
    assert "belongs to the browser" in out, "the browser session is not the CLI session"
    assert "verified by the control plane, not by this CLI" in out
    assert _stored_token(env) == "sess-oidc-1"


def test_saml_browser_flow_confirms_the_token_before_storing_it(
        monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/auth/sso/status"): (200, STATUS_ON_SAML, {}),
        ("GET", "/api/v1/auth/saml/login"): (200, {
            "idp_sso_url": "https://idp.example/saml/sso", "request_id": "r1",
            "saml_request_b64": "PHJlcT4=", "redirect_to": "https://idp.example/saml/sso?SAMLRequest=x"}, {}),
        ("GET", "/api/v1/auth/me"): (200, {"username": "ada", "roles": ["admin"]}, {}),
    })
    monkeypatch.setattr("webbrowser.open", lambda url: True)
    monkeypatch.setattr("getpass.getpass", lambda prompt: "saml-session-token")
    assert run(monkeypatch, transport, "login", "--sso", "--sso-provider", "saml") == 0
    me_call = transport.calls[-1]
    assert me_call[0] == "GET" and me_call[1] == "/api/v1/auth/me"
    assert me_call[2].get("Authorization") == "Bearer saml-session-token", \
        "the pasted token is confirmed live before anything is stored"
    out = capsys.readouterr().out
    assert "https://idp.example/saml/sso?SAMLRequest=x" in out
    assert "token field" in out
    assert _stored_token(env) == "saml-session-token"


def test_sso_relay_file_sends_the_token_from_the_file_not_argv(monkeypatch, env):
    token_file = env["tmp"] / "idp.token"
    token_file.write_text("  file-idp-token \n")
    transport = FakeControlPlane({
        ("POST", "/api/v1/auth/oidc"): (200, LOGIN_OK, {}),
    })
    assert run(monkeypatch, transport, "login",
               "--sso-token-file", str(token_file)) == 0
    (method, path, _h, body), = transport.calls
    assert method == "POST" and path == "/api/v1/auth/oidc"
    assert json.loads(body) == {"token": "file-idp-token"}
    assert _stored_token(env) == "sess-oidc-1"


def test_sso_relay_reads_stdin_with_dash(monkeypatch, env):
    transport = FakeControlPlane(
        {("POST", "/api/v1/auth/oidc"): (200, LOGIN_OK, {})})
    monkeypatch.setattr("sys.stdin", io.StringIO("stdin-idp-token\n"))
    assert run(monkeypatch, transport, "login", "--sso-token-file", "-") == 0
    assert json.loads(transport.calls[0][3]) == {"token": "stdin-idp-token"}


def test_sso_relay_missing_file_refuses_without_storing(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "login",
               "--sso-token-file", str(env["tmp"] / "nope.token")) == 3
    assert "cannot read the id_token source" in capsys.readouterr().err
    assert _stored_token(env) is None
    assert transport.calls == []


def test_no_browser_suppresses_the_launch(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/auth/sso/status"): (200, STATUS_ON_OIDC, {}),
        ("GET", "/api/v1/auth/oidc/authorize"): (
            302, b"", {"Location": "https://idp.example/authorize"}),
        ("POST", "/api/v1/auth/oidc"): (200, LOGIN_OK, {}),
    })
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    monkeypatch.setattr("getpass.getpass", lambda prompt: "idp.token")
    assert run(monkeypatch, transport, "login", "--sso", "--no-browser") == 0
    assert opened == [], "--no-browser must not launch anything"
    assert "browser launch suppressed" in capsys.readouterr().out


def test_empty_paste_stores_nothing(monkeypatch, env, capsys):
    transport = FakeControlPlane({
        ("GET", "/api/v1/auth/sso/status"): (200, STATUS_ON_SAML, {}),
        ("GET", "/api/v1/auth/saml/login"): (200, {
            "idp_sso_url": "https://idp.example/sso", "request_id": "r1",
            "saml_request_b64": "eA==", "redirect_to": "https://idp.example/sso"}, {}),
    })
    monkeypatch.setattr("getpass.getpass", lambda prompt: "")
    assert run(monkeypatch, transport, "login", "--sso", "--sso-provider", "saml") == 3
    assert "no token pasted" in capsys.readouterr().err
    assert _stored_token(env) is None

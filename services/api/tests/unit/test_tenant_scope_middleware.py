"""TenantScopeMiddleware must fail closed.

The middleware exists because only ~5 of ~90 routers depend on
``get_tenant_context``; for the rest it is the only thing applying a tenant
filter. Outside a tenant scope the ORM guard in ``db.tenancy`` is inert, so
letting a request through unscoped means it reads *every* tenant's rows.

These tests pin the two refusals that used to be swallowed into an unscoped
request: a member sending another tenant's id (404) and a member of two
tenants sending no header (400). Neither may reach the downstream app.

The middleware is pure ASGI and is not installed when ENVIRONMENT=test (see
api.main), so it is driven directly here rather than through the app fixture.
"""
from __future__ import annotations

import json

import pytest

from api.dependencies import TenantResolutionRefused
from api.middleware.tenant_scope import TenantScopeMiddleware


def _scope(path: str = "/api/v1/scans"):
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
    }


async def _receive():  # pragma: no cover - never awaited on the refusal path
    return {"type": "http.request", "body": b"", "more_body": False}


class _Recorder:
    """Collects the ASGI messages the middleware sends."""

    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)

    @property
    def status(self):
        return next(m["status"] for m in self.messages if m["type"] == "http.response.start")

    @property
    def body(self):
        return json.loads(
            b"".join(m.get("body", b"") for m in self.messages if m["type"] == "http.response.body")
        )


class _DownstreamSpy:
    """Stands in for the rest of the app; records whether it was reached."""

    def __init__(self):
        self.called = False
        self.tenant_at_call = "<not called>"

    async def __call__(self, scope, receive, send):
        from db.tenancy import current_tenant

        self.called = True
        self.tenant_at_call = current_tenant()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})


def _middleware(app, resolver, monkeypatch):
    """TenantScopeMiddleware with tenant resolution replaced by ``resolver``."""
    import api.dependencies as dependencies

    monkeypatch.setattr(dependencies, "resolve_tenant_for_request", resolver)
    return TenantScopeMiddleware(app)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "detail"),
    [
        (404, "Unknown tenant"),          # member sent another tenant's X-Tenant-ID
        (400, "Multiple tenant memberships — send X-Tenant-ID"),
        (403, "No tenant membership — ask your organization owner for an invite"),
        (423, "This organization is suspended — contact platform support"),
        (503, "Tenant scope unavailable"),  # tenancy tables unreachable
    ],
)
async def test_refusal_never_reaches_the_app_unscoped(status_code, detail, monkeypatch):
    """A refused resolution is answered here, not run without a tenant filter."""

    def _refuse(_request):
        raise TenantResolutionRefused(status_code, detail)

    spy = _DownstreamSpy()
    recorder = _Recorder()
    await _middleware(spy, _refuse, monkeypatch)(_scope(), _receive, recorder)

    assert not spy.called, "request ran unscoped — it would read every tenant's rows"
    assert recorder.status == status_code
    assert recorder.body == {"detail": detail}


@pytest.mark.asyncio
async def test_resolved_tenant_is_active_downstream(monkeypatch):
    """The happy path still enters the scope the ORM guard reads."""
    spy = _DownstreamSpy()
    recorder = _Recorder()
    await _middleware(spy, lambda _r: "tenant-a", monkeypatch)(_scope(), _receive, recorder)

    assert spy.called
    assert spy.tenant_at_call == "tenant-a"


@pytest.mark.asyncio
async def test_principal_with_no_tenant_proceeds_unscoped(monkeypatch):
    """Platform operators and unauthenticated requests legitimately have none."""
    spy = _DownstreamSpy()
    recorder = _Recorder()
    await _middleware(spy, lambda _r: None, monkeypatch)(_scope(), _receive, recorder)

    assert spy.called
    assert spy.tenant_at_call is None


@pytest.mark.asyncio
async def test_non_api_paths_skip_resolution_entirely(monkeypatch):
    """Health/static must not pay for a membership lookup."""

    def _explode(_request):  # pragma: no cover - must never be called
        raise AssertionError("resolution attempted on a skipped path")

    spy = _DownstreamSpy()
    recorder = _Recorder()
    await _middleware(spy, _explode, monkeypatch)(_scope("/health"), _receive, recorder)

    assert spy.called

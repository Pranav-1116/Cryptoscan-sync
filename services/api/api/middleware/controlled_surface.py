"""Fail-closed API support boundary for the controlled deployment profile.

This is deliberately an allowlist, not a claim that every legacy acquisition,
import, graph, export or notification consumer has been qualified. Unsupported
API paths remain available in development, never as a production fallback.
"""
import re
from starlette.responses import JSONResponse
from db.repositories.execution_control import required, enforced_profile


class ControlledSurfaceMiddleware:
    def __init__(self, app, prefix="/api/v1", production=False):
        self.app = app
        self.production = production
        self.prefix = prefix.rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket" and (self.production or required()):
            await send({"type": "websocket.close", "code": 1008, "reason": "Realtime adapter is not qualified for controlled profile"})
            return
        if scope["type"] != "http" or not (self.production or required()):
            await self.app(scope, receive, send)
            return
        path, method = scope.get("path", ""), scope.get("method", "GET")
        if not path.startswith("/api/") or method == "OPTIONS":
            await self.app(scope, receive, send)
            return
        tail = path[len(self.prefix):] if path.startswith(self.prefix + "/") else None
        allowed = tail is not None and (
            (tail.startswith("/auth/") and not tail.startswith("/auth/audit")) or tail.startswith("/execution-controls/")
            or tail.startswith("/assurance/") and method in {"GET", "POST", "PUT"}
            or tail == "/scans/trigger" and method == "POST"
            or method in {"GET", "HEAD"} and (
                re.fullmatch(r"/jobs(?:/[0-9a-f-]{36}(?:/logs)?)?", tail)
                or re.fullmatch(r"/scans(?:/[0-9a-f-]{36}(?:/(?:verify|export))?)?", tail)
                or re.fullmatch(r"/findings(?:/[0-9a-f-]{36}(?:/verify)?)?", tail)
                or tail in {"/health", "/healthz", "/readyz", "/livez"}
            )
            or method == "POST" and re.fullmatch(r"/jobs/[0-9a-f-]{36}/retry", tail)
        )
        if not allowed:
            response = JSONResponse({"detail": "This API surface has no qualified controlled-profile adapter; no legacy fallback is permitted",
                                     "profile": "local-source/v1"}, status_code=409)
            await response(scope, receive, send)
            return
        with enforced_profile():
            if method in {"GET", "HEAD"} and tail.startswith(("/jobs", "/scans", "/findings", "/execution-controls/approvals", "/execution-controls/attempts", "/execution-controls/events")):
                # Storage-region assertions are also checked before disclosing
                # private history, not only before executing new work. A stop
                # does not prevent incident/history access in the right region.
                from db.connection.session import SessionLocal
                from db.tenancy import tenant_scope
                from db.repositories.execution_control import policy_for, ExecutionDenied
                from api.dependencies import resolve_tenant_for_request, TenantResolutionRefused
                from starlette.concurrency import run_in_threadpool
                from starlette.requests import Request
                def admit_history():
                    # Do not infer NULL/platform ownership merely because an
                    # optional outer middleware has not set a ContextVar yet.
                    owner = resolve_tenant_for_request(Request(scope))
                    with tenant_scope(owner), SessionLocal() as session:
                        policy_for(session, owner, allow_stopped=True)
                try:
                    await run_in_threadpool(admit_history)
                except TenantResolutionRefused as exc:
                    await JSONResponse({"detail": exc.detail}, status_code=exc.status_code)(scope, receive, send)
                    return
                except ExecutionDenied as exc:
                    await JSONResponse({"detail": str(exc)}, status_code=409)(scope, receive, send)
                    return
                except Exception:
                    await JSONResponse({"detail": "History residency admission unavailable"}, status_code=503)(scope, receive, send)
                    return
            await self.app(scope, receive, send)

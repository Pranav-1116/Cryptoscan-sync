"""Fresh selected-estate authority for read-only WebSocket history.

No fallback to an unscoped read on auth/DB failure. API-key upgrade quota is
charged once; frame checkpoints recheck credentials and policy, not quota.
"""

from dataclasses import dataclass

from fastapi import HTTPException
from starlette.requests import Request

READER_ROLES = ("admin", "superadmin", "security_analyst", "auditor", "readonly")


class SocketRefused(Exception):
    def __init__(self, reason="Socket credential or selected estate refused", code=1008):
        super().__init__(reason)
        self.code = code


@dataclass(frozen=True)
class SocketGrant:
    principal: str
    tenant_id: str | None
    credential_id: str | None


def resolve_socket(websocket, *, admit=False):
    from api.dependencies import _resolve_tenant_context, _token_from_request
    from api.middleware.tenant_scope import _ws_scope_with_query_headers
    from api.security.rbac import normalize_roles
    from db.connection.session import SessionLocal
    from db.models.tenant import Tenant
    from db.repositories.api_key_repository import ApiKeyRepository
    from db.repositories.user_repository import UserRepository

    scope = _ws_scope_with_query_headers(websocket.scope)
    request = Request({**scope, "method": "GET", "state": {}})
    raw = request.headers.get("x-api-key")
    if not raw and not (
        request.headers.get("authorization")
        or request.cookies.get("cryptoscan_session")
        or request.cookies.get("session_token")
    ):
        raise SocketRefused("No credentials: send an API key or session token")
    try:
        with SessionLocal() as db:
            if raw:
                row = ApiKeyRepository(db).get_by_raw(raw.strip())
                if row is None:
                    raise SocketRefused()
                roles = row.role_list
                owner = row.tenant_id
                selected = request.headers.get("x-tenant-id", "").strip() or None
                if selected is not None and selected != owner:
                    raise SocketRefused()
                if owner is not None:
                    tenant = db.get(Tenant, owner, populate_existing=True)
                    if tenant is None or tenant.status != "ACTIVE":
                        raise SocketRefused()
                from apikeys.policy import KeyPolicy, method_allowed, path_in_scope
                from api.security.client_ip import client_ip
                from identity.api_key_guard import ip_allowed

                policy = KeyPolicy.from_row(row)
                if not (
                    path_in_scope(request.url.path, policy.scopes)
                    and method_allowed("GET", policy.methods)
                    and ip_allowed(client_ip(request), row.allowed_ips)
                ):
                    raise SocketRefused()
                principal, credential_id = f"apikey:{row.name}", row.id
            else:
                from api.security.session_manager import SessionManager
                from datetime import datetime, timezone

                token = _token_from_request(request)
                principal = SessionManager().validate_session(token) if token else None
                stored = UserRepository(db).get_session(token) if principal else None
                if stored is None or stored.username != principal or stored.revoked_at is not None:
                    raise SocketRefused()
                expires = stored.expires_at
                if expires is None:
                    raise SocketRefused()
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires <= datetime.now(timezone.utc):
                    raise SocketRefused()
                user = UserRepository(db).get_by_username(principal)
                if user is None or not user.is_active:
                    raise SocketRefused()
                # A persistent active identity with reader roles is required;
                # missing/deleted users and lookup faults are not env-admins.
                roles = user.role_list
                ctx = _resolve_tenant_context(request, principal, db)
                owner, credential_id = ctx.tenant_id, None
                if owner is not None:
                    tenant = db.get(Tenant, owner, populate_existing=True)
                    if tenant is None or tenant.status != "ACTIVE":
                        raise SocketRefused()
            normalized = set(normalize_roles(roles))
            if not normalized.intersection(normalize_roles(READER_ROLES)):
                raise SocketRefused("Socket requires reader roles; credential roles: " + (", ".join(roles) or "none"))
            if raw and admit and policy.rate_per_minute > 0:
                from api.quota import DbQuotaWindow

                allowed, _, _ = DbQuotaWindow(db).check_and_consume(row.id, policy.rate_per_minute)
                if not allowed:
                    raise SocketRefused("Socket upgrade quota exceeded")
            return SocketGrant(principal, owner, credential_id)
    except SocketRefused:
        raise
    except HTTPException as exc:
        raise SocketRefused() from exc
    except Exception as exc:
        raise SocketRefused("Socket authority unavailable", code=1011) from exc


def visible_event(event, owner):
    """Envelope ownership is authority; payload tenant labels cannot promote it."""
    declared = event.get("tenant_id")
    if declared is not None and not isinstance(declared, str):
        return False
    payload = event.get("payload") or {}
    if not isinstance(payload, dict):
        return False
    if payload.get("tenant_id") is not None and payload["tenant_id"] != declared:
        return False
    return declared == owner

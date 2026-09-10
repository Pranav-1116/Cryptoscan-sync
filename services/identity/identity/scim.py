"""SCIM 2.0 deterministic user provisioning logic (RFC 7643/7644 core).

Pure mapping between SCIM User/Group resources and the local user store, with
strict, deterministic validation. No ML. The HTTP layer (router) calls these
functions; they operate on a repository-like ``user_store`` so they are fully
unit-testable with a fake.

The SCIM bearer token must be the platform admin/provisioner credential — the
router enforces that; this module enforces schema and role rules.
"""

from __future__ import annotations

from typing import Any, Protocol

# SCIM standard schemas
SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

# The platform role carried in a SCIM enterprise attribute. We read roles from
# the standard `roles` array (each value's `value`) and/or a `groups` mapping.
VALID_ROLES = (
    "superadmin", "ciso", "security_analyst", "developer", "auditor",
    "business_owner", "scanner", "readonly", "admin", "viewer",
)


class ScimError(ValueError):
    def __init__(self, status: int, detail: str, scim_type: str = "invalidValue"):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


class UserStore(Protocol):
    def get_by_username(self, username: str) -> Any: ...
    def create_user(self, username: str, password_hash: str, *, roles: list[str],
                    display_name: str | None = None, email: str | None = None,
                    active: bool = True) -> Any: ...
    def set_roles(self, username: str, roles: list[str]) -> Any: ...
    def set_active(self, username: str, active: bool) -> Any: ...
    def soft_delete(self, username: str) -> Any: ...
    def list_all(self) -> list[Any]: ...


# --------------------------------------------------------------------------- #
def _emails(resource: dict) -> str | None:
    for mail in resource.get("emails") or []:
        if isinstance(mail, dict) and mail.get("value"):
            return str(mail["value"]).lower()
        if isinstance(mail, str) and mail:
            return mail.lower()
    return None


def _roles(resource: dict) -> list[str]:
    roles: list[str] = []
    for r in resource.get("roles") or []:
        val = r.get("value") if isinstance(r, dict) else r
        if val:
            roles.append(str(val))
    # also honour explicit `userType`/enterprise group mapping
    return roles


def _validate_username(user_name: str | None) -> str:
    if not user_name or not str(user_name).strip():
        raise ScimError(400, "userName is required", "invalidValue")
    name = str(user_name).strip()
    if len(name) < 2 or len(name) > 100:
        raise ScimError(400, "userName must be 2-100 characters", "invalidValue")
    if any(c.isspace() for c in name) or any(c in name for c in ";\n\r\"'<>"):
        raise ScimError(400, "userName contains illegal characters", "invalidValue")
    return name


def _normalize_scim_roles(roles: list[str]) -> list[str]:
    from identity.ldap_auth import normalize_roles

    out = normalize_roles(roles)
    # SCIM provisioning must never mint a superadmin from a directory sync.
    out = [r for r in out if r != "superadmin"]
    return out or ["readonly"]


def to_scim_user(row: Any) -> dict[str, Any]:
    roles = getattr(row, "role_list", None) or []
    return {
        "schemas": [SCHEMA_USER],
        "id": getattr(row, "username", ""),
        "userName": getattr(row, "username", ""),
        "displayName": getattr(row, "display_name", None) or getattr(row, "username", ""),
        "emails": ([{"value": getattr(row, "email", ""), "primary": True}]
                   if getattr(row, "email", None) else []),
        "active": bool(getattr(row, "is_active", True)),
        "roles": [{"value": r, "type": "direct"} for r in roles],
        "meta": {"resourceType": "User"},
    }


def create_scim_user(store: UserStore, resource: dict[str, Any]) -> dict[str, Any]:
    if SCHEMA_USER not in (resource.get("schemas") or []) and "userName" not in resource:
        raise ScimError(400, "missing SCIM User schema", "invalidSyntax")
    username = _validate_username(resource.get("userName"))
    if store.get_by_username(username) is not None:
        raise ScimError(409, f"user {username} already exists", "uniqueness")
    email = _emails(resource)
    if email and ("@" not in email or len(email) > 320):
        raise ScimError(400, "invalid email", "invalidValue")
    roles = _normalize_scim_roles(_roles(resource))
    display = resource.get("displayName")
    # SCIM does not carry our local password; set an unguessable hash (SSO/LDAP
    # is the path in). Active flag honoured.
    import secrets as _secrets

    from api.security.passwords import hash_password

    active = bool(resource.get("active", True))
    user = store.create_user(
        username,
        hash_password(_secrets.token_urlsafe(48)),
        roles=roles,
        display_name=str(display) if display else None,
        email=email,
        active=active,
    )
    return to_scim_user(user)


def patch_scim_user(store: UserStore, username: str, ops: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply SCIM PATCH Operations (replace/add/delete) deterministically."""
    user = store.get_by_username(username)
    if user is None:
        raise ScimError(404, f"user {username} not found")
    roles = list(getattr(user, "role_list", []) or [])
    active = bool(getattr(user, "is_active", True))
    email = getattr(user, "email", None)
    getattr(user, "display_name", None)
    for op in ops or []:
        op_name = (op.get("op") or "").lower()
        path = op.get("path") or ""
        value = op.get("value")
        if op_name in ("replace", "add"):
            if path == "active":
                active = bool(value)
            elif path == "userName":
                raise ScimError(400, "userName cannot be renamed", "mutability")
            elif path in ("roles", ""):
                incoming = _roles({"roles": value}) if isinstance(value, list) else _roles(op.get("value") or {})
                if op_name == "replace":
                    roles = incoming
                else:
                    roles = roles + incoming
            elif path.startswith("emails"):
                email = (_emails({"emails": value}) if isinstance(value, list) else None) or email
            elif path == "displayName":
                str(value)
        elif op_name == "delete":
            if path == "active":
                active = False
    roles = _normalize_scim_roles(roles)
    store.set_roles(username, roles)
    store.set_active(username, active)
    refreshed = store.get_by_username(username)
    return to_scim_user(refreshed)


def deactivate_scim_user(store: UserStore, username: str) -> dict[str, Any]:
    user = store.get_by_username(username)
    if user is None:
        raise ScimError(404, f"user {username} not found")
    store.set_active(username, False)
    # also revoke sessions by soft-deleting downstream; store handles cascade
    try:
        store.soft_delete(username)
    except Exception:  # pragma: no cover - set_active already disables login
        pass
    return to_scim_user(store.get_by_username(username) or user)


def list_scim_users(store: UserStore, *, start_index: int = 1, count: int = 100,
                    filter_expr: str | None = None) -> dict[str, Any]:
    rows = list(store.list_all())
    resources = [to_scim_user(r) for r in rows]
    # minimal filter: userName eq "x" or emails.value co "x"
    if filter_expr:
        resources = _apply_filter(resources, filter_expr)
    total = len(resources)
    start = max(1, start_index)
    page = resources[start - 1:start - 1 + max(0, count)]
    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": total,
        "itemsPerPage": len(page),
        "startIndex": start,
        "Resources": page,
    }


def _apply_filter(resources: list[dict], expr: str) -> list[dict]:
    expr = expr.strip()
    # supports: userName eq "v"  /  emails.value co "v"  /  active eq true
    for op in (" eq ", " co ", " sw "):
        if op in expr:
            attr, _, raw = expr.partition(op)
            attr = attr.strip()
            val = raw.strip().strip('"').strip("'").lower()
            out = []
            for res in resources:
                if attr == "userName":
                    hay = str(res.get("userName", "")).lower()
                elif attr.startswith("emails"):
                    hay = " ".join(e.get("value", "") for e in res.get("emails", [])).lower()
                elif attr == "active":
                    hay = str(res.get("active", "")).lower()
                else:
                    hay = ""
                if op.strip() == "eq":
                    if hay == val:
                        out.append(res)
                else:
                    if val in hay:
                        out.append(res)
            return out
    return resources

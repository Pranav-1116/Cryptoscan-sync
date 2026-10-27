"""LDAP / Active Directory bind authentication with deterministic group→role
mapping.

The network call is isolated behind ``LdapBackend`` so the mapping/validation
logic is fully unit-testable without a directory server. Production uses
``ldap3`` (imported lazily); tests inject ``FakeLdapBackend``.

Flow (deterministic):
1. Bind with the service account (or anonymously if no bind_dn).
2. Search for the user entry matching ``user_search_filter`` → get its DN and
   attributes (mail, displayName, memberOf).
3. Re-bind as that user DN with the supplied password to prove the credential.
4. Resolve roles from the user's groups via the configured group→role map.
   Fail closed: no mapped group → least-privilege ``readonly``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class LdapError(ValueError):
    """Raised for any bind/search/mapping failure (auth denied)."""


@dataclass
class LdapIdentity:
    nameid: str                       # the directory username / sAMAccountName
    user_dn: str
    email: str | None = None
    display_name: str | None = None
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)


class LdapBackend(Protocol):
    def search_user(self, *, base: str, filter_template: str,
                    username: str) -> dict[str, Any] | None: ...

    def verify_bind(self, user_dn: str, password: str) -> bool: ...


# Canonical CryptoScan roles the identity layer may grant. Kept local so this
# package has no dependency on the API service (avoids import cycles); the API
# re-normalizes these when minting the session.
_VALID_ROLES = frozenset({
    "superadmin", "ciso", "security_analyst", "developer", "auditor",
    "business_owner", "scanner", "readonly",
})
_ROLE_ALIASES = {"admin": "superadmin", "viewer": "readonly"}


def normalize_roles(roles: list[str] | tuple[str, ...] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in roles or []:
        role = str(raw or "").strip().lower()
        if not role:
            continue
        role = _ROLE_ALIASES.get(role, role)
        if role not in _VALID_ROLES or role in seen:
            continue
        seen.add(role)
        out.append(role)
    return out


# --------------------------------------------------------------------------- #
# pure mapping logic (testable, no IO)
# --------------------------------------------------------------------------- #
def apply_group_role_map(groups: list[str], group_role_map: dict[str, str]) -> list[str]:
    """Map LDAP group DNs/CNs to CryptoScan roles. Case-insensitive keys.

    Accepts either full DNs ("CN=SecurityAdmins,OU=Groups,...") or bare group
    names ("SecurityAdmins"); matching is on a case-insensitive substring of
    the group CN against the configured key. Unknown groups are ignored.
    """
    def cn_of(group: str) -> str:
        g = group.strip()
        if "=" in g and g.upper().startswith("CN="):
            return g.split(",", 1)[0][3:].strip().lower()
        return g.lower()

    roles: list[str] = []
    for group in groups or []:
        cn = cn_of(group)
        for key, role in (group_role_map or {}).items():
            k = key.strip().lower()
            if cn == k or k in cn or cn in k:
                roles.append(role)
    normalized = normalize_roles(roles)
    return normalized or ["readonly"]


def build_identity(*, username: str, user_dn: str, attributes: dict[str, Any],
                   group_role_map: dict[str, str]) -> LdapIdentity:
    def _first(value: Any) -> str | None:
        if isinstance(value, (list, tuple)):
            return str(value[0]) if value else None
        return str(value) if value else None

    email = _first(attributes.get("mail")) or _first(attributes.get("userPrincipalName"))
    display = _first(attributes.get("displayName")) or _first(attributes.get("cn"))
    member_of = attributes.get("memberOf") or attributes.get("groups") or []
    if isinstance(member_of, str):
        member_of = [member_of]
    groups = [str(g) for g in member_of]
    roles = apply_group_role_map(groups, group_role_map)
    return LdapIdentity(
        nameid=username,
        user_dn=user_dn,
        email=email,
        display_name=display,
        groups=groups,
        roles=roles,
    )


def authenticate_with_backend(
    backend: LdapBackend,
    *,
    username: str,
    password: str,
    user_search_base: str,
    user_search_filter: str,
    group_role_map: dict[str, str],
) -> LdapIdentity:
    if not username or not password:
        raise LdapError("username and password are required")
    if any(c in username for c in ";\n\r\"'()"):
        # hard block filter-injection characters before building the filter
        raise LdapError("invalid characters in username")

    entry = backend.search_user(
        base=user_search_base,
        filter_template=user_search_filter,
        username=username,
    )
    if not entry:
        raise LdapError("user not found in directory")
    user_dn = entry.get("dn") or ""
    if not user_dn:
        raise LdapError("directory entry has no DN")

    if not backend.verify_bind(user_dn, password):
        raise LdapError("bind failed (invalid credentials)")

    return build_identity(
        username=username,
        user_dn=user_dn,
        attributes=entry.get("attributes") or {},
        group_role_map=group_role_map,
    )


# --------------------------------------------------------------------------- #
# production backend using ldap3 (lazy import) — only used at runtime
# --------------------------------------------------------------------------- #
class Ldap3Backend:  # pragma: no cover - exercised against a real directory
    def __init__(self, uri: str, bind_dn: str, bind_password: str, *, use_ssl: bool | None = None):
        try:
            import ldap3  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise LdapError("ldap3 is not installed; cannot authenticate against LDAP") from exc
        self._ldap3 = ldap3
        self.uri = uri
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.use_ssl = use_ssl if use_ssl is not None else uri.lower().startswith("ldaps")

    def _connect(self) -> Any:
        server = self._ldap3.Server(self.uri, use_ssl=self.use_ssl, get_info=None)
        conn = self._ldap3.Connection(server, user=self.bind_dn or None,
                                      password=self.bind_password or None,
                                      auto_bind=False, receive_timeout=10)
        if not conn.bind():
            raise LdapError(f"service bind failed: {conn.result}")
        return conn

    def search_user(self, *, base: str, filter_template: str, username: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            filt = filter_template.replace("{username}", _escape_filter(username))
            conn.search(base, filt, attributes=["*"])
            if not conn.entries:
                return None
            entry = conn.entries[0]
            attrs = {k.lower(): v.values for k, v in entry.entry_attributes_as_dict.items()}
            return {"dn": entry.entry_dn, "attributes": attrs}
        finally:
            conn.unbind()

    def verify_bind(self, user_dn: str, password: str) -> bool:
        server = self._ldap3.Server(self.uri, use_ssl=self.use_ssl, get_info=None)
        conn = self._ldap3.Connection(server, user=user_dn, password=password, auto_bind=False)
        try:
            return bool(conn.bind())
        finally:
            conn.unbind()


def _escape_filter(value: str) -> str:
    """RFC4515 filter escaping to stop LDAP filter injection."""
    out = []
    for ch in value:
        out.append({
            "\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29",
            "\x00": "\\00",
        }.get(ch, ch))
    return "".join(out)


def authenticate_ldap(*, uri: str, bind_dn: str, bind_password: str, username: str,
                      password: str, user_search_base: str, user_search_filter: str,
                      group_search_base: str = "", group_membership_filter: str = "",
                      group_role_map: dict[str, str] | None = None,
                      backend: LdapBackend | None = None) -> LdapIdentity:
    """Authenticate a user against LDAP/AD and map groups → roles.

    ``backend`` is injectable for tests/air-gapped validation; production
    constructs an ``Ldap3Backend`` from the URI/credentials.
    """
    be = backend or Ldap3Backend(uri, bind_dn, bind_password)
    return authenticate_with_backend(
        be,
        username=username,
        password=password,
        user_search_base=user_search_base or "",
        user_search_filter=user_search_filter or "(sAMAccountName={username})",
        group_role_map=group_role_map or {},
    )


# --------------------------------------------------------------------------- #
# deterministic fake backend for tests / local validation
# --------------------------------------------------------------------------- #
class FakeLdapBackend:
    """In-memory directory: {username: (dn, password, attributes)}."""

    def __init__(self, users: dict[str, dict[str, Any]]):
        self.users = users

    def search_user(self, *, base: str, filter_template: str, username: str) -> dict[str, Any] | None:
        user = self.users.get(username)
        if not user:
            return None
        return {"dn": user["dn"], "attributes": user.get("attributes", {})}

    def verify_bind(self, user_dn: str, password: str) -> bool:
        for entry in self.users.values():
            if entry["dn"] == user_dn and entry.get("password") == password:
                return True
        return False

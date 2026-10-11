"""Pluggable external secret resolution (advanced/75 P0#1, round 31).

Credential settings today come from the environment — which means every
secret sits in a deployment manifest. This module adds the reference
layer report 75 asked for: any credential value may instead be a
``reference`` resolved through a provider —

    env:NAME            the literal environment variable NAME
    file:/path          the file's contents (Docker/K8s secret mounts)
    vault://mount/path/key
                        HashiCorp Vault KV-v2 read:
                        GET {VAULT_ADDR}/v1/{mount}/data/{path}
                        with X-Vault-Token — a REAL client for a REAL
                        vault; no vault configured means the reference
                        fails loudly, it never resolves to "".

Fail-loud contract: an unresolvable reference raises
SecretResolutionError at startup (never an silently-empty credential),
and no resolved value is ever logged or returned by the status surface.

Rotation bookkeeping: every resolution records provider + reference +
timestamp (never the value), so /security/secrets/status can report
which credentials are external and when they were last resolved — the
inventory half of report 75's rotation story. Rotation itself (the
vault side re-keying) stays with the external system, honestly.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Protocol

logger = logging.getLogger(__name__)


class SecretResolutionError(ValueError):
    """A reference could not be resolved — fail loud, never empty."""


@dataclass
class ResolutionRecord:
    """Bookkeeping for one resolved reference (never the value)."""
    provider: str
    reference: str
    resolved_at: str
    outcome: str  # OK | FAILED


@dataclass
class ResolutionLog:
    records: list[ResolutionRecord] = field(default_factory=list)

    def add(self, provider: str, reference: str, outcome: str) -> None:
        self.records.append(ResolutionRecord(
            provider=provider, reference=reference, outcome=outcome,
            resolved_at=datetime.now(timezone.utc).isoformat(),
        ))

    def report(self) -> list[dict[str, Any]]:
        return [
            {"provider": r.provider, "reference": r.reference,
             "resolved_at": r.resolved_at, "outcome": r.outcome}
            for r in self.records
        ]


class SecretProvider(Protocol):
    name: str
    scheme: str

    def resolve(self, reference: str) -> str: ...


class EnvProvider:
    """``env:NAME`` — the literal environment variable."""

    name = "env"
    scheme = "env:"

    def resolve(self, reference: str) -> str:
        var = reference[len(self.scheme):]
        if not var:
            raise SecretResolutionError("env: reference needs a variable name")
        value = os.environ.get(var)
        if value is None or value == "":
            raise SecretResolutionError(f"environment variable '{var}' is not set")
        return value


class FileProvider:
    """``file:/path`` — Docker/Kubernetes secret mounts, no env exposure."""

    name = "file"
    scheme = "file:"

    def resolve(self, reference: str) -> str:
        path = reference[len(self.scheme):]
        if not path:
            raise SecretResolutionError("file: reference needs a path")
        try:
            with open(path, encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError as exc:
            raise SecretResolutionError(f"secret file '{path}' unreadable: {exc}") from exc
        if not value:
            raise SecretResolutionError(f"secret file '{path}' is empty")
        return value


class VaultKVProvider:
    """``vault://mount/path/key`` — HashiCorp Vault KV v2 over HTTP.

    Uses stdlib urllib against ``VAULT_ADDR`` (VAULT_TOKEN required).
    A missing VAULT_ADDR/VAULT_TOKEN or any transport failure raises —
    the caller decides whether that is fatal (startup resolution) or
    reportable (status probe). No value caching: a rotation on the
    vault side is picked up at the next resolution.
    """

    name = "vault"
    scheme = "vault://"

    def __init__(
        self,
        *,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        kv_mount: Optional[str] = None,
        timeout: float = 5.0,
        fetch: Optional[Callable[[str, str, str, str, float], Any]] = None,
    ) -> None:
        self._addr = addr
        self._token = token
        self._kv_mount = kv_mount
        self._timeout = timeout
        # injectable transport for tests: (method, url, headers, body, timeout)
        self._fetch = fetch or self._http_fetch

    def _config(self) -> tuple[str, str, str]:
        from api.config.settings import get_settings

        settings = get_settings()
        addr = (self._addr or settings.VAULT_ADDR or "").rstrip("/")
        token = self._token or settings.VAULT_TOKEN or ""
        mount = self._kv_mount or settings.VAULT_KV_MOUNT or "secret"
        return addr, token, mount

    @staticmethod
    def _http_fetch(method: str, url: str, headers: dict[str, str], _body: str, timeout: float) -> Any:
        import urllib.error
        import urllib.request

        request = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as exc:
            raise SecretResolutionError(f"vault unreachable at {url}: {exc}") from exc

    def resolve(self, reference: str) -> str:
        rest = reference[len(self.scheme):]
        parts = rest.split("/")
        if len(parts) < 3:
            raise SecretResolutionError(
                "vault:// reference needs mount/path/key (got "
                f"'{reference}')")
        mount, path, key = parts[0], "/".join(parts[1:-1]), parts[-1]
        addr, token, default_mount = self._config()
        mount = mount or default_mount
        if not addr or not token:
            raise SecretResolutionError(
                "vault:// reference but VAULT_ADDR/VAULT_TOKEN not configured")
        url = f"{addr}/v1/{mount}/data/{path}"
        status, body = self._fetch("GET", url, {"X-Vault-Token": token}, "", self._timeout)
        if status != 200:
            raise SecretResolutionError(
                f"vault read failed (HTTP {status}) for {url}")
        try:
            payload = json.loads(body)
            value = ((payload.get("data") or {}).get("data") or {}).get(key)
        except json.JSONDecodeError as exc:
            raise SecretResolutionError(f"vault returned non-JSON for {url}") from exc
        if value is None or str(value) == "":
            raise SecretResolutionError(f"vault secret {reference} has no key '{key}'")
        return str(value)


#: reference schemes recognised by the default registry
DEFAULT_PROVIDERS: tuple[SecretProvider, ...] = (EnvProvider(), FileProvider(), VaultKVProvider())


def is_reference(value: str) -> bool:
    """True when a credential value is a provider reference."""
    return isinstance(value, str) and (
        value.startswith("env:") or value.startswith("file:") or value.startswith("vault://")
    )


def resolve_secret(value: str, *, providers: tuple[SecretProvider, ...] = DEFAULT_PROVIDERS,
                   log: Optional[ResolutionLog] = None) -> str:
    """Resolve one credential value. Plain values pass through unchanged."""
    if not is_reference(value):
        return value
    for provider in providers:
        if value.startswith(provider.scheme):
            try:
                resolved = provider.resolve(value)
            except SecretResolutionError:
                if log is not None:
                    log.add(provider.name, value, "FAILED")
                raise
            if log is not None:
                log.add(provider.name, value, "OK")
            return resolved
    raise SecretResolutionError(f"no provider registered for reference '{value}'")


def resolve_settings_secrets(*, providers: tuple[SecretProvider, ...] = DEFAULT_PROVIDERS,
                             strict: bool = True) -> dict[str, Any]:
    """Resolve reference-valued settings in place at startup.

    Walks the loaded APISettings object; every field whose value is a
    reference is replaced by its resolution. ``strict=True`` (startup)
    raises on the FIRST unresolvable reference — a half-resolved
    credential set must not boot. Returns a report (references only,
    never values).
    """
    from api.config.settings import get_settings

    settings = get_settings()
    if getattr(settings, "VAULT_PROVIDERS_DISABLED", False):
        return {"resolved": 0, "disabled": True, "records": []}
    log = ResolutionLog()
    resolved_fields: list[str] = []
    failures: list[dict[str, str]] = []
    for name in sorted(type(settings).model_fields):
        raw = getattr(settings, name, None)
        if not is_reference(raw or ""):
            continue
        try:
            value = resolve_secret(raw, providers=providers, log=log)
        except SecretResolutionError as exc:
            failures.append({"field": name, "reference": raw, "error": str(exc)})
            if strict:
                raise
            continue
        try:
            object.__setattr__(settings, name, value)
            resolved_fields.append(name)
        except Exception as exc:  # noqa: BLE001 — frozen/protected field
            failures.append({"field": name, "reference": raw, "error": f"not writable: {exc}"})
            if strict:
                raise SecretResolutionError(f"settings field {name} not writable") from exc
    return {
        "resolved": len(resolved_fields),
        "resolved_fields": resolved_fields,
        "failures": failures,
        "records": log.report(),
    }


def secret_status() -> dict[str, Any]:
    """Introspection for the admin status endpoint — NO values, ever.

    Probes every reference-valued setting without mutating it, so an
    operator can see which credentials are external and whether they
    currently resolve.
    """
    from api.config.settings import get_settings

    settings = get_settings()
    entries: list[dict[str, Any]] = []
    if getattr(settings, "VAULT_PROVIDERS_DISABLED", False):
        return {"enabled": False, "providers": [], "references": []}
    vault_configured = bool((settings.VAULT_ADDR or "").strip() and (settings.VAULT_TOKEN or "").strip())
    for name in sorted(type(settings).model_fields):
        raw = getattr(settings, name, None)
        if not is_reference(raw or ""):
            continue
        provider = next((p for p in DEFAULT_PROVIDERS if raw.startswith(p.scheme)), None)
        entry: dict[str, Any] = {
            "field": name,
            "reference": raw,
            "provider": provider.name if provider else "unknown",
            "resolves": False,
            "error": None,
        }
        try:
            resolve_secret(raw)
            entry["resolves"] = True
        except SecretResolutionError as exc:
            entry["error"] = str(exc)
        entries.append(entry)
    return {
        "enabled": True,
        "providers": [
            {"name": p.name, "scheme": p.scheme} for p in DEFAULT_PROVIDERS
        ],
        "vault_configured": vault_configured,
        "references": entries,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "note": "values are never exposed; vault rotation happens on the vault side",
    }

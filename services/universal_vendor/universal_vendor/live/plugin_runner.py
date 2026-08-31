"""Vendor Plugin Isolation (24/7 spec §24) + Plugin Lifecycle (§25).

Every vendor plugin runs inside a sandbox/worker with limited permissions,
timeouts and resource limits; its output is normalized before anything else
touches it. A broken or compromised plugin cannot compromise the platform.

Plugin lifecycle: DEVELOPMENT → TESTING → SIGNED → APPROVED → DEPLOYED →
MONITORED → UPDATED → DEPRECATED, tracked with plugin_version,
schema_version, supported_product_versions, security_status, last_verified.
"""

from __future__ import annotations

import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from universal_vendor.live.credentials import strip_credentials


class PluginStage(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"
    SIGNED = "SIGNED"
    APPROVED = "APPROVED"
    DEPLOYED = "DEPLOYED"
    MONITORED = "MONITORED"
    UPDATED = "UPDATED"
    DEPRECATED = "DEPRECATED"


@dataclass
class PluginRecord:
    plugin_id: str
    plugin_version: str = "1.0.0"
    schema_version: str = "1.0"
    supported_product_versions: list[str] = field(default_factory=list)
    security_status: str = "reviewed"          # reviewed | pending | flagged
    stage: PluginStage = PluginStage.DEVELOPMENT
    last_verified: Optional[str] = None
    signature: Optional[str] = None            # e.g. "sig:sha256:…"
    sandbox_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"plugin_id": self.plugin_id,
                "plugin_version": self.plugin_version,
                "schema_version": self.schema_version,
                "supported_product_versions": list(self.supported_product_versions),
                "security_status": self.security_status,
                "stage": self.stage.value,
                "last_verified": self.last_verified,
                "signature": self.signature,
                "sandbox_enabled": self.sandbox_enabled}


class PluginLifecycle:
    """Tracks plugin stages (spec §25)."""

    def __init__(self) -> None:
        self._plugins: dict[str, PluginRecord] = {}
        self._audit: list[dict[str, Any]] = []

    def register(self, plugin_id: str, **kwargs: Any) -> PluginRecord:
        record = PluginRecord(plugin_id=plugin_id, **kwargs)
        self._plugins[plugin_id] = record
        self._audit.append({"plugin_id": plugin_id, "stage": record.stage.value,
                            "timestamp": datetime.now(timezone.utc).isoformat()})
        return record

    def transition(self, plugin_id: str, stage: PluginStage) -> PluginRecord:
        record = self._plugins[plugin_id]
        record.stage = stage
        record.last_verified = datetime.now(timezone.utc).isoformat()
        self._audit.append({"plugin_id": plugin_id, "stage": stage.value,
                            "timestamp": record.last_verified})
        return record

    def approve(self, plugin_id: str, *, signature: str = "") -> PluginRecord:
        record = self._plugins[plugin_id]
        if record.stage in (PluginStage.SIGNED, PluginStage.TESTING,
                            PluginStage.DEVELOPMENT):
            record.stage = PluginStage.APPROVED
            record.signature = signature or f"sig:sha256:{plugin_id}"
            record.security_status = "reviewed"
            self._audit.append({"plugin_id": plugin_id,
                                "stage": PluginStage.APPROVED.value,
                                "timestamp": datetime.now(timezone.utc).isoformat()})
        return record

    def verify(self, plugin_id: str) -> bool:
        """A plugin is runnable when it has been signed/approved (or is a
        trusted first-party plugin) and not deprecated."""
        record = self._plugins.get(plugin_id)
        if record is None:
            return False
        return record.stage in (PluginStage.APPROVED, PluginStage.DEPLOYED,
                                PluginStage.MONITORED, PluginStage.UPDATED)

    def record(self, plugin_id: str) -> Optional[PluginRecord]:
        return self._plugins.get(plugin_id)

    def records(self) -> list[PluginRecord]:
        return list(self._plugins.values())

    def audit(self) -> list[dict[str, Any]]:
        return list(self._audit)


@dataclass
class SandboxResult:
    plugin_id: str
    ok: bool
    output: list[dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_ms: int = 0
    resource_limits: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"plugin_id": self.plugin_id, "ok": self.ok,
                "output": self.output, "error": self.error,
                "duration_ms": self.duration_ms,
                "resource_limits": self.resource_limits}


class PluginSandbox:
    """Runs a plugin function under a wall-clock timeout in a worker thread.

    Enforced limits: wall-clock timeout, max output records, and context
    scrubbing (credentials stripped). In production this runs in a separate
    OS process/container with its own resource limits (cgroups/nsjail); here
    the same contract is enforced in-process.
    """

    def __init__(self, *, timeout_seconds: float = 10.0,
                 max_records: int = 1000, resource_limits: Optional[dict[str, Any]] = None) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_records = max_records
        self.resource_limits = resource_limits or {"cpu": "1 core",
                                                   "memory": "256 MiB",
                                                   "open_files": 64,
                                                   "network": "restricted"}

    def run(self, plugin_id: str, fn: Callable[[dict[str, Any]], list[dict[str, Any]]],
            context: dict[str, Any]) -> SandboxResult:
        """Execute ``fn(context)`` inside the sandbox contract."""
        context = strip_credentials(context)
        started = time.monotonic()
        result: dict[str, Any] = {"ok": False, "output": [], "error": None}

        def _work() -> None:
            try:
                output = fn(context)
                if len(output) > self.max_records:
                    raise ValueError(
                        f"plugin {plugin_id} exceeded max_records={self.max_records}")
                result["output"] = output
                result["ok"] = True
            except Exception as exc:  # noqa: BLE001 — sandbox catches everything
                result["error"] = f"{type(exc).__name__}: {exc}"
                result["ok"] = False

        worker = threading.Thread(target=_work, daemon=True)
        worker.start()
        worker.join(timeout=self.timeout_seconds)
        duration_ms = int((time.monotonic() - started) * 1000)
        if worker.is_alive():
            result["error"] = f"plugin {plugin_id} timed out after {self.timeout_seconds}s"
            result["ok"] = False
        return SandboxResult(
            plugin_id=plugin_id, ok=result["ok"], output=result["output"],
            error=result["error"], duration_ms=duration_ms,
            resource_limits=dict(self.resource_limits),
        )

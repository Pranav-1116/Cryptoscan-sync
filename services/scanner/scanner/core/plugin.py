"""Discovery plugin contract. Scanners implement this; the worker orchestrates."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DiscoveryPlugin(Protocol):
    plugin_id: str
    plugin_version: str

    def capabilities(self) -> list[str]: ...

    def validate_configuration(self) -> None: ...

    def authenticate(self) -> None: ...

    def discover(self, target: str, **kwargs: Any) -> list[Any]: ...

    def collect_evidence(self, observations: list[Any]) -> list[Any]: ...

    def normalize(self, raw: list[Any]) -> list[dict[str, Any]]: ...

    def health_check(self) -> dict[str, Any]: ...


_REGISTRY: dict[str, type] = {}


def register_plugin(cls: type) -> type:
    plugin_id = getattr(cls, "plugin_id", None) or cls.__name__
    _REGISTRY[str(plugin_id)] = cls
    return cls


def registered_plugins() -> dict[str, type]:
    return dict(_REGISTRY)


@register_plugin
class JavaSourcePlugin:
    """Filesystem Java discovery. No credentials. No live network."""

    plugin_id = "static-java-scanner"
    plugin_version = "1.0.0"

    def capabilities(self) -> list[str]:
        return ["source_code", "java", "filesystem"]

    def validate_configuration(self) -> None:
        return None

    def authenticate(self) -> None:
        return None

    def discover(self, target: str, **kwargs: Any) -> list[Any]:
        from pathlib import Path

        from scanner.parsers.java_parser import parse_java_file

        root = Path(str(target).replace("local://", "").replace("file://", ""))
        findings: list[Any] = []
        if root.is_file() and root.suffix == ".java":
            return parse_java_file(root, root.parent)
        if not root.is_dir():
            return []
        for path in root.rglob("*.java"):
            try:
                findings.extend(parse_java_file(path, root))
            except Exception:
                continue
        return findings

    def collect_evidence(self, observations: list[Any]) -> list[Any]:
        return list(observations)

    def normalize(self, raw: list[Any]) -> list[dict[str, Any]]:
        from shared_models.observation import observation_from_raw_finding

        return [observation_from_raw_finding(item).to_dict() for item in raw]

    def health_check(self) -> dict[str, Any]:
        return {"plugin_id": self.plugin_id, "ok": True, "version": self.plugin_version}

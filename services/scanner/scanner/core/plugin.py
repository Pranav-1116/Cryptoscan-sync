"""Discovery plugin contract. Scanners implement this; the worker orchestrates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable


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


def plugin_catalog() -> list[dict[str, Any]]:
    rows = []
    for cls in _REGISTRY.values():
        plugin = cls()
        rows.append(
            {
                "plugin_id": plugin.plugin_id,
                "plugin_version": plugin.plugin_version,
                "capabilities": plugin.capabilities(),
                "health": plugin.health_check(),
            }
        )
    return rows


def observations_from_findings(findings: list[Any], *, scan_id: str | None = None) -> list[dict[str, Any]]:
    from shared_models.observation import observation_from_raw_finding

    return [observation_from_raw_finding(item, scan_id=scan_id).to_dict() for item in findings]


def _root(target: str) -> Path:
    return Path(str(target).replace("local://", "").replace("file://", ""))


class FilesystemLanguagePlugin:
    """Shared discover() for suffix-scoped source scanners."""

    plugin_id = "static-source-scanner"
    plugin_version = "1.0.0"
    language = "source"
    extensions: tuple[str, ...] = ()
    parser: Callable[..., list[Any]] | None = None

    def capabilities(self) -> list[str]:
        return ["source_code", self.language, "filesystem"]

    def validate_configuration(self) -> None:
        return None

    def authenticate(self) -> None:
        return None

    def discover(self, target: str, **kwargs: Any) -> list[Any]:
        parser = self.parser
        if parser is None:
            return []
        root = _root(target)
        findings: list[Any] = []
        if root.is_file() and root.suffix.lower() in self.extensions:
            try:
                return parser(root, root.parent)
            except Exception:
                return []
        if not root.is_dir():
            return []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.extensions:
                continue
            try:
                findings.extend(parser(path, root))
            except Exception:
                continue
        return findings

    def collect_evidence(self, observations: list[Any]) -> list[Any]:
        return list(observations)

    def normalize(self, raw: list[Any]) -> list[dict[str, Any]]:
        return observations_from_findings(raw)

    def health_check(self) -> dict[str, Any]:
        return {"plugin_id": self.plugin_id, "ok": True, "version": self.plugin_version}


@register_plugin
class JavaSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-java-scanner"
    language = "java"
    extensions = (".java",)

    @property
    def parser(self):
        from scanner.parsers.java_parser import parse_java_file

        return parse_java_file


@register_plugin
class PythonSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-python-scanner"
    language = "python"
    extensions = (".py",)

    @property
    def parser(self):
        from scanner.parsers.python_parser import parse_python_file

        return parse_python_file


@register_plugin
class JavaScriptSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-js-scanner"
    language = "javascript"
    extensions = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

    @property
    def parser(self):
        from scanner.parsers.javascript_parser import parse_javascript_file

        return parse_javascript_file


@register_plugin
class CSharpSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-csharp-scanner"
    language = "csharp"
    extensions = (".cs",)

    @property
    def parser(self):
        from scanner.parsers.csharp_parser import parse_csharp_file

        return parse_csharp_file

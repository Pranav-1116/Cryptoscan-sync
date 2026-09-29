"""Discovery plugin contract. Scanners implement this; the worker orchestrates."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


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
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
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


@register_plugin
class GoSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-go-scanner"
    language = "go"
    extensions = (".go",)

    @property
    def parser(self):
        from scanner.parsers.go_parser import parse_go_file

        return parse_go_file


@register_plugin
class PhpSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-php-scanner"
    language = "php"
    extensions = (".php",)

    @property
    def parser(self):
        from scanner.parsers.php_parser import parse_php_file

        return parse_php_file


@register_plugin
class RubySourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-ruby-scanner"
    language = "ruby"
    extensions = (".rb",)

    @property
    def parser(self):
        from scanner.parsers.ruby_parser import parse_ruby_file

        return parse_ruby_file


@register_plugin
class RustSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-rust-scanner"
    language = "rust"
    extensions = (".rs",)

    @property
    def parser(self):
        from scanner.parsers.rust_parser import parse_rust_file

        return parse_rust_file


@register_plugin
class CSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-c-scanner"
    language = "c"
    extensions = (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".m", ".mm")

    @property
    def parser(self):
        from scanner.parsers.c_parser import parse_c_file

        return parse_c_file


@register_plugin
class KotlinSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-kotlin-scanner"
    language = "kotlin"
    extensions = (".kt", ".kts", ".scala")

    @property
    def parser(self):
        from scanner.parsers.kotlin_parser import parse_kotlin_file

        return parse_kotlin_file


@register_plugin
class ConfigSourcePlugin(FilesystemLanguagePlugin):
    plugin_id = "static-config-scanner"
    language = "config"
    extensions = (".conf", ".cnf", ".yml", ".yaml", ".properties", ".env", ".ini", ".tf", ".tfvars", ".cfg")

    def discover(self, target: str, **kwargs: Any) -> list[Any]:
        from scanner.parsers.config_crypto_parser import parse_config_file, scan_config_tree

        root = _root(target)
        if not root.exists():
            return []
        try:
            if root.is_file():
                return parse_config_file(root, root.parent)
            return scan_config_tree(root, root)
        except Exception:
            return []

    @property
    def parser(self):
        from scanner.parsers.config_crypto_parser import parse_config_file

        return parse_config_file

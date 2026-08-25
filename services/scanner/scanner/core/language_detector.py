"""Detect source languages present in a repository."""

from __future__ import annotations

from pathlib import Path

from scanner.core.file_discovery import FileDiscovery

LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "JAVA": (".java",),
    "PYTHON": (".py",),
    "JAVASCRIPT": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    "CSHARP": (".cs",),
    "GO": (".go",),
    "PHP": (".php",),
    "RUBY": (".rb",),
    "RUST": (".rs",),
}

MARKER_FILES: dict[str, tuple[str, ...]] = {
    "JAVA": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "PYTHON": ("pyproject.toml", "requirements.txt", "setup.py"),
    "JAVASCRIPT": ("package.json", "tsconfig.json"),
    "CSHARP": (".csproj", ".sln"),
    "GO": ("go.mod", "go.sum"),
    "PHP": ("composer.json",),
    "RUBY": ("Gemfile",),
    "RUST": ("Cargo.toml",),
}


def detect_languages_in_repo(root_path: str | Path) -> list[str]:
    root = Path(root_path)
    found: list[str] = []
    discovery = FileDiscovery()
    files = list(discovery.discover(root))
    names = {p.name.lower() for p in root.rglob("*") if p.is_file()}

    for language, exts in LANGUAGE_EXTENSIONS.items():
        if any(p.suffix.lower() in exts for p in files):
            found.append(language)
            continue
        markers = MARKER_FILES.get(language, ())
        if any(any(name.endswith(marker.lower()) for marker in markers) for name in names):
            found.append(language)
    return found

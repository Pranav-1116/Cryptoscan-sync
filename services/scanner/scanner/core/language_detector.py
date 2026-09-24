"""Detect source languages present in a repository."""

from __future__ import annotations

from pathlib import Path

from scanner.core.file_discovery import FileDiscovery

LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "JAVA": (".java",),
    "KOTLIN": (".kt", ".kts"),
    "SCALA": (".scala",),
    "PYTHON": (".py",),
    "JAVASCRIPT": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    "CSHARP": (".cs",),
    "GO": (".go",),
    "PHP": (".php",),
    "RUBY": (".rb",),
    "RUST": (".rs",),
    "C": (".c", ".h"),
    "CPP": (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
    "OBJECTIVE_C": (".m", ".mm"),
    "SWIFT": (".swift",),
    "SHELL": (".sh", ".bash", ".zsh", ".ksh"),
    "SQL": (".sql", ".pls", ".plsql", ".pks", ".pkb", ".prc", ".fnc", ".trg", ".tsql", ".ddl", ".psql", ".pgsql"),
    "PLI": (".pli", ".pl1", ".plx"),
    "RPG": (".rpgle", ".sqlrpgle", ".rpg", ".rpg38", ".rpg36", ".rpgleinc", ".rpginc", ".sqlrpg"),
    "CL": (".clle", ".clp", ".cllp", ".clle38", ".cl"),
    "COBOL": (".cbl", ".cob", ".cobol", ".cpy", ".pco", ".sqb", ".jcl"),
}

MARKER_FILES: dict[str, tuple[str, ...]] = {
    "JAVA": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "KOTLIN": ("settings.gradle.kts",),
    "PYTHON": ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"),
    "JAVASCRIPT": ("package.json", "tsconfig.json", "pnpm-lock.yaml", "yarn.lock"),
    "CSHARP": (".csproj", ".sln"),
    "GO": ("go.mod", "go.sum"),
    "PHP": ("composer.json", "composer.lock"),
    "RUBY": ("Gemfile", "Gemfile.lock"),
    "RUST": ("Cargo.toml", "Cargo.lock"),
    "C": ("CMakeLists.txt", "configure.ac", "Makefile.am", "meson.build"),
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

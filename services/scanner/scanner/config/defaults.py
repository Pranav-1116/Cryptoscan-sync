"""Default exclusion patterns for static discovery."""

from __future__ import annotations

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "target",
        "build",
        "out",
        ".idea",
        ".gradle",
        "bin",
        "dist",
        "venv",
        ".venv",
        "vendor",
    }
)

DEFAULT_TEST_DIRS = frozenset({"test", "tests", "Test", "Tests", "it", "integration-test"})

DEFAULT_SOURCE_EXTENSIONS = (
    ".java",
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".cs",
)

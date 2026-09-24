"""File discovery - walk directory tree and find Java source files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

import structlog

logger = structlog.get_logger(__name__)

# Default directories to exclude from scanning
DEFAULT_EXCLUDED_DIRS = frozenset({
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "target",           # Maven build output
    "build",            # Gradle build output
    "out",              # IntelliJ build output
    ".idea",            # IntelliJ project files
    ".gradle",
    "bin",
    "dist",
    "venv",
    ".venv",
    "vendor",
})

# Directories likely to contain generated or test code (configurable exclusion)
DEFAULT_TEST_DIRS = frozenset({
    "test",
    "tests",
    "Test",
    "Tests",
    "it",               # Integration tests in Maven
    "integration-test",
})


DEFAULT_SOURCE_EXTENSIONS = (
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".cs",
    ".go",
    ".php",
    ".rb",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".cxx",
    ".hpp",
    ".hh",
    ".hxx",
    ".m",
    ".mm",
    # deployment / framework configuration carries TLS, SSH, JWT and cipher
    # settings that never appear in source: scanned by config_crypto_parser
    ".conf",
    ".cnf",
    ".yml",
    ".yaml",
    ".properties",
    ".env",
    ".ini",
    ".tf",
    ".tfvars",
    ".cfg",
)

_NAMED_CONFIG_EXACT = frozenset({
    "dockerfile", "containerfile", ".env", "nginx.conf", "openssl.cnf", "ssh_config", "sshd_config",
    "postgresql.conf", "pg_hba.conf", "my.cnf", "redis.conf", "haproxy.cfg", "httpd.conf", "apache2.conf",
    "krb5.conf", "ipsec.conf", "strongswan.conf", "smb.conf", "ldap.conf", "slapd.conf",
})


def is_named_config_file(name: str) -> bool:
    """Suffix-less / well-known config files the config parser should read
    (``Dockerfile``, ``api.Dockerfile``, ``.env.production``, ``sshd_config`` ...)."""
    low = name.lower()
    if low in _NAMED_CONFIG_EXACT:
        return True
    if low.startswith(("dockerfile", "containerfile", ".env.", "sshd_config", "ssh_config")):
        return True
    return low.endswith((".dockerfile", "_config"))


class FileDiscovery:
    """
    Discovers source files in a directory tree.
    
    Implements configurable exclusion of:
    - Build output directories
    - Version control directories
    - Test directories (optional)
    - Generated code directories (optional)
    """

    def __init__(
        self,
        exclude_dirs: frozenset[str] | None = None,
        exclude_test_dirs: bool = False,
        max_file_size_mb: float = 10.0,
        extensions: tuple[str, ...] | None = None,
    ):
        self._excluded_dirs = exclude_dirs or DEFAULT_EXCLUDED_DIRS
        if exclude_test_dirs:
            self._excluded_dirs = self._excluded_dirs | DEFAULT_TEST_DIRS
        self._max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self._extensions = tuple(extensions) if extensions else DEFAULT_SOURCE_EXTENSIONS

    def discover(self, root_path: Path) -> Iterator[Path]:
        """
        Yield all Java source files under root_path.
        
        Args:
            root_path: Root directory to scan
            
        Yields:
            Path objects for each .java file found
        """
        if not root_path.exists():
            raise FileNotFoundError(f"Root path does not exist: {root_path}")
        if not root_path.is_dir():
            raise ValueError(f"Root path must be a directory: {root_path}")

        log = logger.bind(root=str(root_path))
        log.info("starting_file_discovery")

        file_count = 0
        skip_count = 0

        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
            # Modify dirnames IN PLACE to prevent os.walk from descending into excluded dirs
            dirnames[:] = [
                d for d in dirnames
                if d not in self._excluded_dirs and not d.startswith(".")
            ]

            current_dir = Path(dirpath)

            for filename in filenames:
                if not filename.lower().endswith(self._extensions) and not is_named_config_file(filename):
                    continue

                file_path = current_dir / filename

                # Skip oversized files
                try:
                    file_size = file_path.stat().st_size
                    if file_size > self._max_file_size_bytes:
                        log.warning(
                            "skipping_oversized_file",
                            file=str(file_path),
                            size_mb=file_size / (1024 * 1024),
                        )
                        skip_count += 1
                        continue
                except OSError as e:
                    log.warning("cannot_stat_file", file=str(file_path), error=str(e))
                    skip_count += 1
                    continue

                file_count += 1
                yield file_path

        log.info(
            "file_discovery_complete",
            files_found=file_count,
            files_skipped=skip_count,
        )

    def count_files(self, root_path: Path) -> int:
        """Count Java files without yielding them (for progress estimation)."""
        return sum(1 for _ in self.discover(root_path))
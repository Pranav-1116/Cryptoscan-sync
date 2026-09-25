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

_OUTPUT_DIR_NAMES = frozenset({"build", "out", "target", "dist", "bin"})
ARCHIVE_EXTENSIONS = (".jar", ".war", ".ear", ".aar", ".dll", ".exe", ".netmodule", ".winmd")
ARCHIVE_MAX_BYTES = 250 * 1024 * 1024

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
    ".gradle",
    ".groovy",
    ".vue",
    ".svelte",
    ".swift",
    ".xml",
    ".config",
    ".csproj",
    ".props",
    ".plist",
    ".entitlements",
    ".sh",
    ".sql", ".pls", ".plsql", ".pks", ".pkb", ".prc", ".fnc", ".trg", ".tsql", ".ddl", ".psql", ".pgsql", ".spb", ".sps", ".tps", ".tpb", ".bdy", ".spc",
    ".cbl", ".cob", ".cobol", ".cpy", ".pco", ".sqb", ".ccp", ".jcl", ".proc", ".rexx", ".rex", ".asm",
    ".pli", ".pl1", ".plx", ".pls1",
    ".nsp", ".nsn", ".nss", ".nsh", ".nsc", ".nsl", ".nsa", ".nsg", ".nsm", ".nat",  # Software AG Natural
    ".4gl", ".per", ".sru", ".srw", ".srf", ".sra", ".srd", ".srs", ".srm", ".srq", ".p", ".w", ".i", ".cls", ".tal", ".tacl", ".ptal", ".sas", ".hsm",  # Informix 4GL, PowerBuilder, OpenEdge ABL, NonStop TAL/TACL, SAS, payShield console
    ".csd", ".rdo", ".sit", ".proclib", ".hwscfg", ".ttls", ".pagent",  # CICS / IMS / AT-TLS definitions
    ".rpgle", ".sqlrpgle", ".rpg", ".rpg38", ".rpg36", ".rpgleinc", ".rpginc", ".sqlrpg", ".clle", ".clp", ".cllp", ".clle38", ".cl", ".cblle", ".sqlcblle", ".cbl38",
    ".jar", ".war", ".ear", ".aar", ".class", ".dll", ".exe", ".netmodule", ".winmd",
    ".bash",
    ".zsh",
    ".ksh",
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
    # templated configuration (Go templates, Jinja/Ansible, Helm) still carries
    # literal ssl_protocols / ssl_ciphers / Ciphers directives
    ".tmpl",
    ".tpl",
    ".j2",
    ".toml",
    ".props",
    ".mqsc",
    ".security",
    ".policy",
    ".settings",
)

_NAMED_CONFIG_EXACT = frozenset({
    "dockerfile", "containerfile", ".env", "nginx.conf", "openssl.cnf", "ssh_config", "sshd_config",
    "postgresql.conf", "pg_hba.conf", "my.cnf", "redis.conf", "haproxy.cfg", "httpd.conf", "apache2.conf",
    "krb5.conf", "ipsec.conf", "strongswan.conf", "smb.conf", "ldap.conf", "slapd.conf",
    "java.security", "ssl.client.props", "ssl.server.props", "sas.client.props", "soap.client.props", "mqclient.ini", "qm.ini", "mqs.ini", "server.env", "jvm.options", "bootstrap.properties",
    "quickfix.cfg", "acceptor.cfg", "initiator.cfg", "weblogic.policy", "setdomainenv.sh", "startweblogic.sh",
})


SHELL_NAMED_FILES = frozenset({"makefile", "gnumakefile", "justfile", "entrypoint", "docker-entrypoint"})


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
        # Runtime evidence (ICSF/RACF/payShield/JSSE/openssl/web-server/sshd logs) is opt-in:
        # log trees are large and repetitive, and a bank hands them over separately.
        if os.environ.get("CRYPTOSCAN_RUNTIME_LOGS", "").lower() in ("1", "true", "yes"):
            self._extensions = self._extensions + (".log", ".trc", ".audit", ".syslog")

    def _is_excluded_dir(self, path: Path) -> bool:
        name = path.name
        if name not in self._excluded_dirs:
            return False
        # ``build`` / ``out`` / ``target`` / ``dist`` / ``bin`` are build *outputs* by
        # convention, but they are also ordinary source package names
        # (pip/_internal/operations/build/). A directory that is a Python package
        # is source, not output.
        if name in _OUTPUT_DIR_NAMES and (path / "__init__.py").is_file():
            return False
        return True

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
                if not d.startswith(".") and not self._is_excluded_dir(Path(dirpath) / d)
            ]

            current_dir = Path(dirpath)

            for filename in filenames:
                if (
                    not filename.lower().endswith(self._extensions)
                    and not is_named_config_file(filename)
                    and filename.lower() not in SHELL_NAMED_FILES
                ):
                    continue

                file_path = current_dir / filename

                # Skip oversized files
                try:
                    file_size = file_path.stat().st_size
                    limit = self._max_file_size_bytes
                    if filename.lower().endswith(ARCHIVE_EXTENSIONS):
                        limit = max(limit, ARCHIVE_MAX_BYTES)  # vendored fat JARs / EARs are routinely 50-200 MB
                    if file_size > limit:
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
"""CLI = OPERATE. Console = INVESTIGATE. API = INTEGRATE.

Three front doors, one control plane. That is the architecture the docs assert,
and it is easy to erode: the console is a browser client, the API is the router
layer, and the CLI is a program that — if it ever imported the estate, discovery
or database modules directly — would become a *second* implementation of
authorisation, tenancy and evidence chaining, reachable without any of them.

`services/api/api/cli.py` is that second implementation, and it is allowed to
exist: it is the in-process operator CLI, registered only on a host that owns the
database, and it takes an injected `session_factory` so tests can drive it
without a server. What must not happen is the *bank-facing* CLI drifting into it.

`services/api/api/cli_remote.py` is the bank-facing one. It speaks HTTP and
nothing else. This file is the check, because
`docs/bank-environment/98-cli-architecture.md` claimed the split was "enforced by
module structure" while no test read the module structure at all.

It also pins the two things that make the CLI real rather than decorative:

* every literal API path the remote CLI builds is a path the app serves
  (``api_contract`` now scans both CLI files — before this, only ``scripts/`` and
  ``integrations/`` were scanned, so the CLIs an operator actually runs were
  outside the route contract entirely);
* the commands the architecture doc documents are commands the parser defines.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import api_contract as contract  # noqa: E402

REMOTE_CLI = ROOT / "services" / "api" / "api" / "cli_remote.py"
LOCAL_CLI = ROOT / "services" / "api" / "api" / "cli.py"

#: What the bank-facing CLI may import. Standard library is not listed (it is
#: discovered from ``sys.stdlib_module_names``); these are the only non-stdlib
#: names permitted, and each has a reason.
ALLOWED_IMPORTS = {
    "shared_models": (
        "release_signature — verifying a bundle's detached signature is a pure "
        "function; it reads no database and no estate"
    ),
    "cryptography": (
        "bundle encryption/decryption of the export directory in transit; no key "
        "material leaves the operator's terminal"
    ),
    "yaml": "reading the release manifest it verifies",
}

#: Prefixes that mean "this CLI reached into the platform itself". Importing any
#: of these would give it a code path that never crosses an authorisation check.
FORBIDDEN_PREFIXES = (
    "db",
    "api.routers",
    "api.dependencies",
    "api.estate_twin_store",
    "universal_platform",
    "agility",
    "discovery",
    "estate",
    "evidence",
    "shared_config",
    "sqlalchemy",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # relative import: same package, so it stays inside the CLI
                names.add("." * node.level + (node.module or ""))
            elif node.module:
                names.add(node.module)
    return names


def _top_level(name: str) -> str:
    return "." * (len(name) - len(name.lstrip("."))) + name.lstrip(".").split(".")[0]


class TestTheRemoteCliIsHttpOnly:
    def test_it_does_not_import_the_platform(self):
        offenders = []
        for name in sorted(_imports(REMOTE_CLI)):
            root = _top_level(name)
            if root in sys.stdlib_module_names or root.startswith("."):
                continue
            if any(root == bad or name.startswith(bad + ".") for bad in FORBIDDEN_PREFIXES):
                offenders.append(name)
        assert offenders == [], (
            "the bank-facing CLI imports the platform directly, which would bypass the "
            f"API's authorisation and tenancy: {offenders}"
        )

    def test_the_allowed_non_standard_imports_are_the_documented_ones(self):
        used = set()
        for name in _imports(REMOTE_CLI):
            root = _top_level(name)
            if root in sys.stdlib_module_names or root.startswith("."):
                continue
            used.add(root)
        assert used <= set(ALLOWED_IMPORTS), (
            f"cli_remote.py gained an undocumented dependency: {sorted(used - set(ALLOWED_IMPORTS))}"
        )
        for root, reason in ALLOWED_IMPORTS.items():
            assert reason.strip()

    def test_it_opens_no_database_session(self):
        source = REMOTE_CLI.read_text(encoding="utf-8")
        for banned in ("session_factory", "SessionLocal", "create_engine", "get_db_session"):
            assert banned not in source, f"cli_remote.py references {banned}"

    def test_it_speaks_http_over_the_documented_transport(self):
        source = REMOTE_CLI.read_text(encoding="utf-8")
        # urllib, not requests: the installed CLI must run on a bare bank host
        assert "urllib.request" in source
        assert "requests" not in _imports(REMOTE_CLI)


class TestTheLocalOperatorCliIsSeparate:
    def test_the_in_process_cli_is_not_the_bank_cli(self):
        """Two modules, two transports — a merge would erase the boundary."""
        assert REMOTE_CLI.exists() and LOCAL_CLI.exists()
        assert REMOTE_CLI.resolve() != LOCAL_CLI.resolve()

    def test_the_in_process_cli_is_injected_a_session(self):
        """It may hold the database, but only through a factory the caller owns."""
        source = LOCAL_CLI.read_text(encoding="utf-8")
        assert "session_factory" in source, (
            "cli.py no longer takes an injected session factory: it would then have to "
            "build its own engine, and the operator path would stop being testable"
        )

    def test_the_remote_cli_does_not_import_the_local_one(self):
        names = _imports(REMOTE_CLI)
        assert not any(name.endswith("api.cli") or name == "cli" for name in names), names


class TestTheCliIsInsideTheRouteContract:
    def test_both_cli_files_are_scanned(self):
        assert set(contract.CLI_SOURCES) == {
            "services/api/api/cli_remote.py",
            "services/api/api/cli.py",
        }
        for name in contract.CLI_SOURCES:
            assert (ROOT / name).exists(), name

    def test_the_remote_cli_calls_are_extracted_and_resolve(self):
        calls = [call for call in contract.script_calls() if "cli_remote.py" in call.where()]
        assert len(calls) >= 55, f"only {len(calls)} CLI calls extracted — did the CLI switch to built paths?"
        broken = contract.unknown(calls)
        assert broken == [], "the CLI calls paths the app does not serve:\n" + "\n".join(
            f"  {call.method} {call.path} at {call.where()}" for call in broken
        )

    def test_a_missing_cli_route_would_be_caught(self):
        """Mutation check: the CLI scan must fail on a path nobody implemented."""
        fake = contract.Call(
            "/api/v1/collection/qualification/this-route-does-not-exist",
            "services/api/api/cli_remote.py",
            1,
        )
        assert contract.unknown([fake]) == [fake]


class TestTheDocumentedCommandsExist:
    """A command an operator is told to run must be a command the parser has.

    `cryptoscan` is one entry point with two command families: the HTTP client in
    ``cli_remote.py`` and the in-process operator in ``cli.py``. ``main()`` routes
    a documented verb to one or the other, and this test reads the *union*, because
    a verb that exists in neither is a command an operator cannot run.
    """

    @staticmethod
    def _defined() -> set[str]:
        import re

        out: set[str] = set()
        for path in (REMOTE_CLI, LOCAL_CLI):
            source = path.read_text(encoding="utf-8")
            out |= {
                m.group(1)
                for m in re.finditer(r'(?:^|[^_.a-z])sub\.add_parser\(\s*"([a-z0-9-]+)"', source)
            }
        return out

    @staticmethod
    def _remote() -> set[str]:
        import re

        source = REMOTE_CLI.read_text(encoding="utf-8")
        return {
            m.group(1)
            for m in re.finditer(r'(?:^|[^_.a-z])sub\.add_parser\(\s*"([a-z0-9-]+)"', source)
        }

    def _documented(self) -> set[str]:
        import re

        doc = (ROOT / "docs" / "bank-environment" / "98-cli-architecture.md").read_text(encoding="utf-8")
        verbs: set[str] = set()
        for line in doc.splitlines():
            match = re.match(r"\s*\$?\s*cryptoscan\s+([a-z][a-z0-9-]*)", line)
            if match:
                verbs.add(match.group(1))
        return verbs

    def test_every_command_the_doc_names_is_defined(self):
        defined = self._defined()
        assert len(defined) >= 20, sorted(defined)
        documented = self._documented()
        assert len(documented) >= 15, sorted(documented)
        missing = sorted(documented - defined)
        assert missing == [], (
            "docs/bank-environment/98-cli-architecture.md tells an operator to run commands no "
            f"parser defines: {missing}"
        )

    def test_the_bank_facing_verbs_are_remotely_defined(self):
        """The verbs an operator runs at a bank go over HTTP, not into a database."""
        remote = self._remote()
        for verb in ("login", "status", "doctor", "target", "jobs", "evidence", "bundle",
                     "report", "pqc", "ci", "scope", "assurance", "explain"):
            assert verb in remote, f"{verb} is not a remote command"

    def test_the_in_process_commands_are_named_as_such(self):
        """`serve` is the one command that is a host operation, and it says so."""
        source = LOCAL_CLI.read_text(encoding="utf-8")
        assert "def _cmd_serve" in source
        doc = (ROOT / "docs" / "bank-environment" / "98-cli-architecture.md").read_text(encoding="utf-8")
        assert "`serve` is the bank-server daemon entry point" in doc
        # ... and it refuses without an explicit PostgreSQL estate
        assert 'is a bank-server service operation' in source

    def test_every_routed_command_has_a_remote_handler(self):
        """`main()` routes verb → handler by name; a rename would be a TypeError at runtime."""
        import re

        source = LOCAL_CLI.read_text(encoding="utf-8")
        routed = set(re.findall(r"cli_remote\.([a-z_]+_remote)\(", source))
        assert routed, "main() no longer routes anything to the remote client"
        handlers = set(re.findall(r"^def ([a-z_]+_remote)\(", REMOTE_CLI.read_text(encoding="utf-8"), re.M))
        assert routed <= handlers, f"main() routes to handlers that are gone: {sorted(routed - handlers)}"

"""One offline transfer path, not three — and the retired one stays retired.

The air-gap story used to have two implementations of the same idea:

* ``/api/v1/enterprise/airgap/{bundle,export,import}`` read live findings out of
  the running control plane, signed the document with a secret supplied **in the
  request body**, and on import verified that signature and answered
  ``{"accepted": true}`` without storing anything;
* ``cryptoscan bundle export`` writes stored evidence, the twin snapshot and the
  BOM projections with a manifest that says what it does not carry.

Only the second is an evidence path — the first could not be audited back to a
collector, and its "import" was indistinguishable from success without doing
anything. The API now answers **410** on the withdrawn paths, naming the
replacement.

These tests keep the decision from decaying in the two directions that matter:
the withdrawn path must not start answering 2xx again (someone "fixing" a client
by restoring the handler), and no shipped caller may quietly start using it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import api_contract as contract  # noqa: E402

WITHDRAWN = (
    "/api/v1/enterprise/airgap/bundle",
    "/api/v1/enterprise/airgap/export",
    "/api/v1/enterprise/airgap/import",
)
SUPPORTED = (
    "/api/v1/resilience/airgap/build-bundle",
    "/api/v1/resilience/airgap/import-feed",
)


def test_the_withdrawn_paths_are_still_routable_but_marked_deprecated():
    """410, not 404: an old client must learn what replaced it."""
    from fastapi.routing import APIRoute

    from api.routers import enterprise

    for path_suffix in ("bundle", "export", "import"):
        handler = getattr(enterprise, f"airgap_{path_suffix}")
        assert handler.__doc__ and "Withdrawn" in handler.__doc__, path_suffix
    routes = [route for route in enterprise.router.routes if isinstance(route, APIRoute)]
    airgap = {route.path.split("/airgap/")[-1]: route for route in routes if "/airgap/" in route.path}
    assert set(airgap) == {"bundle", "export", "import"}
    for suffix, route in airgap.items():
        assert route.deprecated is True, suffix


def test_the_withdrawn_paths_answer_gone_with_a_replacement():
    from api.routers import enterprise

    for suffix in ("bundle", "export", "import"):
        handler = getattr(enterprise, f"airgap_{suffix}")
        try:
            handler(None, user="admin")
        except Exception as exc:  # HTTPException carries the guidance
            detail = getattr(exc, "detail", None)
            assert getattr(exc, "status_code", None) == 410, suffix
            assert detail["withdrawn"].startswith("the live air-gap transfer path")
            assert "bundle export" in detail["evidence_export"]
            assert detail["docs"] == "docs/airgap-deployment.md"
        else:  # pragma: no cover - the handler must not return a payload
            raise AssertionError(f"airgap_{suffix} answered instead of refusing")


def test_the_supported_paths_still_exist():
    served = set(contract.served_paths())
    for path in SUPPORTED:
        assert path in served, path


def test_no_shipped_caller_uses_the_withdrawn_paths():
    """The CLI, the console and the scripts must not point at the retired family."""
    offenders: list[str] = []
    roots = (ROOT / "scripts", ROOT / "frontend" / "src", ROOT / "integrations", ROOT / "services")
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".ts", ".tsx", ".sh", ".yml", ".yaml"}:
                continue
            if "tests" in path.parts or "__pycache__" in path.parts or "node_modules" in path.parts:
                continue
            # the router that defines the withdrawn handlers is where the names live
            if path.name == "enterprise.py" and "routers" in path.parts:
                continue
            # the deprecation registry names the paths in order to MARK them
            # withdrawn (RFC 8594 lifecycle headers on the 410s); it never
            # calls them
            if path.name == "deprecation.py" and "api" in path.parts:
                continue
            # the two generators name the paths in order to MARK them withdrawn in
            # the generated documents; they never call them
            if path.name in {"gen_rest_api.py", "audit_build_status.py"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for banned in WITHDRAWN:
                if banned in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {banned}")
    assert offenders == [], "shipped code still calls the withdrawn transfer path:\n" + "\n".join(offenders)


def test_the_docs_describe_the_withdrawal_and_the_replacement():
    doc = (ROOT / "docs" / "airgap-deployment.md").read_text(encoding="utf-8")
    assert "bundle export" in doc
    assert "410" in doc
    assert "answered 2xx until this" in doc
    # the runbook must not still instruct anyone to call the retired endpoints
    for banned in ("POST /api/v1/enterprise/airgap/bundle", "POST /api/v1/enterprise/airgap/export"):
        assert banned not in doc, banned
    # and the feed path is still the documented way to move advisories in
    assert "/resilience/airgap/import-feed" in doc


def test_the_cli_bundle_states_what_it_does_not_carry():
    """The surviving path's limits are shipped with it, not only in a doc."""
    source = (ROOT / "services" / "api" / "api" / "cli_remote.py").read_text(encoding="utf-8")
    limits = re.search(r"BUNDLE_LIMITS = \[(.*?)\]", source, re.DOTALL)
    assert limits, "BUNDLE_LIMITS missing from the CLI"
    body = limits.group(1)
    assert "not the \"\n" in body or "collectors" in body
    assert "does not make its evidence yours" in body
    for command in ("\"export\"", "\"verify\"", "\"import\""):
        assert command in source


def test_the_generated_route_reference_marks_the_withdrawn_rows():
    """A table that lists a 410 route like any other is a documentation defect.

    Both generated documents (the API reference and the build-status audit) are
    produced from the schema, which still contains the withdrawn operations. Each
    generator therefore has to mark them, or a reader integrates with a route
    that refuses.
    """
    reference = (ROOT / "docs" / "api-reference" / "rest-api.md").read_text(encoding="utf-8")
    audit = (ROOT / "docs" / "bank-environment" / "95-build-status-audit.md").read_text(encoding="utf-8")
    for path in (
        "/api/v1/enterprise/airgap/bundle",
        "/api/v1/enterprise/airgap/export",
        "/api/v1/enterprise/airgap/import",
    ):
        for doc, name in ((reference, "rest-api.md"), (audit, "95-build-status-audit.md")):
            rows = [line for line in doc.splitlines() if path in line and line.startswith("|")]
            assert rows, f"{name} does not list {path}"
            for row in rows:
                assert "410" in row, f"{name} lists {path} without saying it answers 410: {row}"
    # the replacement is named per direction, not one command for all three
    assert "cryptoscan bundle export" in reference
    assert "cryptoscan bundle verify" in reference
    assert "## Withdrawn routes" in reference

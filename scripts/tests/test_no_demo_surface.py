"""The product ships no demo surface — and cannot quietly grow one again.

The synthetic banking estate, the sample applications, the seed scripts and the
baked-in third-party test pack were useful while the platform was being built.
They are not part of a production product: an operator who sees a "demo" directory
or a seed command has to work out whether the numbers on screen are theirs or
invented, and every shipped fixture is one more thing to explain during a bank's
security review.

This test is the tripwire. It reads the checkout, not the imports, so a demo
artefact cannot return just because nothing currently imports it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: paths that must not exist in a shipped checkout
FORBIDDEN_PATHS = (
    "demo",
    "tools/banking_sandbox",
    "generate_sandbox.py",
    "deploy/bank-sandbox-testpack.json",
    "scripts/seed_demo.py",
    "scripts/seed_test_data.sh",
    "scripts/seed_business_owners.py",
    "scripts/seed_business_processes.py",
    "scripts/seed_compliance_rules.py",
    "scripts/seed_network_targets.py",
    "scripts/polyglot_smoke.py",
    "products/sandbox",
    "products/connector",
    "scripts/connect_bank_sandbox.py",
    "scripts/qualify_tbf.py",
    "scripts/qualify_routed_tbf.py",
    "tools/disposable_tbf",
    "tools/routed_tbf",
    "docs/bank-environment/88-disposable-linux-tbf-qualification.md",
    "docs/bank-environment/89-routed-tbf-application-and-recovery.md",
    "docs/bank-environment/90-synthetic-banking-estate.md",
    "docs/runbooks/disposable-tbf.md",
    "docs/runbooks/routed-tbf.md",
    "docs/proposals/fab-demo-script.md",
    "docs/readiness-evidence/load-balancer-sandbox-2026-10-26.md",
    "docs/readiness-evidence/banking-sandbox-2026-10-26.md",
    "docs/readiness-evidence/banking-sandbox-2026-10-26",
    "docs/readiness-evidence/disposable-tbf-2026-10-26.md",
    "docs/readiness-evidence/disposable-tbf-2026-10-26",
    "docs/readiness-evidence/routed-tbf-2026-10-26.md",
    "docs/readiness-evidence/routed-tbf-2026-10-26",
    "docs/readiness-evidence/connected-lab-2026-10-26",
)

#: modules a product module must never import
FORBIDDEN_IMPORTS = (
    re.compile(r"^\s*(from|import)\s+tools\.banking_sandbox", re.M),
    re.compile(r"^\s*(from|import)\s+tools\.disposable_tbf", re.M),
    re.compile(r"^\s*(from|import)\s+tools\.routed_tbf", re.M),
    re.compile(r"^\s*(from|import)\s+products\.connector", re.M),
    re.compile(r"^\s*from\s+\.\s*demo\s+import", re.M),
    re.compile(r"^\s*import\s+demo\b", re.M),
)

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", ".mypy_cache"}


def _python_files(*roots: str):
    for root in roots:
        for path in (ROOT / root).rglob("*.py"):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path


@pytest.mark.parametrize("relative", FORBIDDEN_PATHS)
def test_no_demo_artefact_ships(relative: str):
    assert not (ROOT / relative).exists(), (
        f"{relative} is a demo/lab artefact and must not ship in the product "
        f"(see docs/architecture/platform-boundaries.md)"
    )


def test_no_product_module_imports_a_demo_module():
    offenders = []
    for path in _python_files("services", "shared", "scripts"):
        if "/tests/" in path.as_posix() or path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in FORBIDDEN_IMPORTS:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")
    assert offenders == []


def test_no_sample_data_script_remains_under_scripts():
    """Any `seed_*` script that reappears is sample data by another name."""
    seeded = sorted(p.name for p in (ROOT / "scripts").glob("seed_*.py"))
    assert seeded == [], (
        "sample-data scripts must not ship; reference data is created from real "
        f"inventory or through the API: {seeded}"
    )


def test_docs_do_not_point_at_removed_lab_paths():
    stale = []
    removed = (
        "tools/banking_sandbox", "generate_sandbox", "seed_demo", "seed_business_owners",
        "seed_business_processes", "seed_compliance_rules", "seed_network_targets",
        "tools/disposable_tbf", "tools/routed_tbf", "connect_bank_sandbox",
        "qualify_routed_tbf", "qualify_tbf", "products/sandbox", "products/connector",
        "fab-demo-script", "connected-lab-2026-10-26",
    )
    for path in (ROOT / "docs").rglob("*.md"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in removed:
            if needle in text:
                stale.append(f"{path.relative_to(ROOT)} -> {needle}")
    assert stale == [], f"documentation references removed demo paths: {stale}"


def test_a_production_boot_with_demo_credentials_is_refused():
    """The default lab credentials can never boot a production instance."""
    from api.config.settings import APISettings, validate_runtime_settings

    settings = APISettings.model_construct(
        ENVIRONMENT="production",
        SECRET_KEY="cryptoscan-dev-secret-key-change-in-production",
        ADMIN_PASSWORD="cryptoscan",
        ADMIN_PASSWORD_HASH="",
        GITHUB_WEBHOOK_SECRET="dev-webhook-secret-change-me-32chars!!",
        METRICS_TOKEN="",
        DATABASE_URL="sqlite:///./data/cryptoscan.db",
        CORS_ORIGINS="*",
        ALLOW_SQLITE=False,
        ALLOW_INSECURE_CORS=False,
        DOCS_ENABLED=None,
        COOKIE_SECURE=None,
    )
    with pytest.raises(RuntimeError, match="production configuration rejected"):
        validate_runtime_settings(settings)

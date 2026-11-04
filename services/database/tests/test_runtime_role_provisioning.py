"""The provisioning script is tested like the boundary it creates.

A runbook paragraph cannot be tested. A script can, and this file is the reason item 13 of the
review is closed: the SQL is checked in, its refusals are asserted, and the "apply proves
nothing" claim is written down where a reviewer will trip over it.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _script():
    spec = importlib.util.spec_from_file_location(
        "provision_runtime_role", ROOT / "scripts" / "provision_runtime_role.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provision = _script()


# --------------------------------------------------------------------------- #
# the SQL
# --------------------------------------------------------------------------- #

def test_the_plan_grant_only_what_the_application_needs():
    steps = {item["step"]: item["sql"] for item in provision.statements("cryptoscan_app", "cryptoscan")}
    assert set(steps) == {"role", "role-flags", "connect", "schema", "tables", "sequences",
                          "default-tables", "default-sequences"}
    assert "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE" in steps["role"]
    assert "GRANT CONNECT ON DATABASE \"cryptoscan\" TO cryptoscan_app" in steps["connect"]
    assert "ALTER DEFAULT PRIVILEGES IN SCHEMA public" in steps["default-tables"]
    joined = " ".join(steps.values())
    # A provisioning script that grants DDL or role creation has undone the boundary.
    for forbidden in ("CREATE ON SCHEMA", "WITH GRANT OPTION", "SUPERUSER;", "BYPASSRLS;"):
        assert forbidden not in joined


def test_the_plan_is_idempotent_so_provisioning_twice_is_a_no_op():
    first = provision.statements("cryptoscan_app", "cryptoscan")
    second = provision.statements("cryptoscan_app", "cryptoscan")
    assert first == second
    assert "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cryptoscan_app')" in first[0]["sql"]


def test_the_plan_carries_no_password_and_no_credential():
    rendered = json.dumps(provision.statements("cryptoscan_app", "cryptoscan"))
    assert "PASSWORD" not in rendered.upper()
    assert "secret" not in rendered.lower()


@pytest.mark.parametrize("role", ["postgres", "root", "cryptoscan", "rdsadmin", "azure_superuser"])
def test_the_plan_refuses_a_bootstrap_or_migration_identity(role):
    with pytest.raises(SystemExit, match="bootstrap or migration identity"):
        provision.statements(role, "cryptoscan")


@pytest.mark.parametrize("role", ["", "Runtime Role", "role; DROP TABLE x", "x'--", "a" * 64])
def test_the_plan_refuses_a_role_name_it_would_have_to_quote_and_hope(role):
    with pytest.raises(SystemExit, match="plain lower-case identifier"):
        provision.statements(role, "cryptoscan")


@pytest.mark.parametrize("database", ["", 'db"; DROP DATABASE x; --', "a b"])
def test_the_plan_refuses_an_unsafe_database_name(database):
    with pytest.raises(SystemExit, match="plain identifier"):
        provision.statements("cryptoscan_app", database)


# --------------------------------------------------------------------------- #
# the verification
# --------------------------------------------------------------------------- #

def test_verification_measures_the_flags_that_decide_whether_rls_binds():
    facts = {q["fact"]: q for q in provision.verification_queries("cryptoscan_app")}
    assert facts["is_superuser"]["expect"] == "false"
    assert facts["bypasses_rls"]["expect"] == "false"
    assert "rolsuper" in facts["is_superuser"]["sql"]
    assert "rolbypassrls" in facts["bypasses_rls"]["sql"]
    # FORCE, not just ENABLE: the table owner is exempt otherwise.
    assert "relforcerowsecurity" in facts["tables_rls_forced"]["sql"]
    assert facts["tables_rls_enabled"]["expect"] == "all"
    assert facts["policies_present"]["expect"] == "more-than-zero"


def test_verification_insists_the_measuring_connection_is_the_runtime_identity():
    facts = provision.verification_queries("cryptoscan_app")
    assertions = {q["fact"]: q["expect"] for q in facts}
    assert assertions["measures_this_role"] == "runtime"
    # and it fails when measured as somebody else
    assert provision._fails({"fact": "measures_this_role", "expect": "runtime",
                             "observed": {"current_user": "postgres"},
                             "role": "cryptoscan_app"}) is True
    assert provision._fails({"fact": "measures_this_role", "expect": "runtime",
                             "observed": {"current_user": "cryptoscan_app"},
                             "role": "cryptoscan_app"}) is False


def test_forced_rls_must_cover_every_table_not_the_convenient_ones():
    assert provision._fails({"fact": "tables_rls_forced", "expect": "all",
                             "observed": {"missing": 3, "total": 120}}) is True
    assert provision._fails({"fact": "tables_rls_forced", "expect": "all",
                             "observed": {"missing": 0, "total": 120}}) is False


# --------------------------------------------------------------------------- #
# the commands
# --------------------------------------------------------------------------- #

def test_apply_refuses_without_an_explicit_acknowledgement(monkeypatch, capsys):
    monkeypatch.delenv("CRYPTOSCAN_PROVISION_ACK", raising=False)
    with pytest.raises(SystemExit, match="CRYPTOSCAN_PROVISION_ACK"):
        provision.main(["apply", "--dsn", "postgresql://dba@db/cryptoscan"])


def test_apply_refuses_a_dsn_with_an_inline_password(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_PROVISION_ACK", "1")
    with pytest.raises(SystemExit, match="inline password"):
        provision.main(["apply", "--dsn", "postgresql://dba:hunter2@db/cryptoscan"])


def test_nothing_that_touches_a_database_runs_without_a_dsn(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_PROVISION_DSN", raising=False)
    with pytest.raises(SystemExit, match="--dsn"):
        provision.main(["verify"])


def test_plan_needs_no_database_at_all(capsys):
    assert provision.main(["plan"]) == 0
    printed = capsys.readouterr().out
    assert "GRANT CONNECT ON DATABASE" in printed
    assert "-- role: a login that is not a superuser and cannot bypass RLS" in printed


def test_plan_json_says_applying_is_not_verifying(capsys):
    assert provision.main(["plan", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "cryptoscan.runtime-role-plan/1"
    assert "does not prove the database binds the role" in payload["note"]
    assert len(payload["statements"]) == 8


def test_the_runbook_points_at_this_script_so_nobody_re_invents_the_sql():
    runbook = ROOT / "docs" / "runbooks" / "onprem-postgres-runtime-role.md"
    text = runbook.read_text(encoding="utf-8")
    assert "scripts/provision_runtime_role.py" in text
    assert "provision_runtime_role.py verify" in text

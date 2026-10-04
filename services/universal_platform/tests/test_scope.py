"""Scope & Authorization + multi-tenant isolation tests (#2, #11).

Pure-logic tests over ``universal_platform.scope`` (no DB): the envelope is
fail-closed and Tenant A cannot read Tenant B.
"""

from __future__ import annotations


from universal_platform.scope import (
    authorize_scope,
    guard_tenant,
    resolve_scope,
)


def _org_row(name="Acme", org_id="o1"):
    return {"id": org_id, "name": name}


def _entries():
    return [
        {"kind": "network", "target": "10.0.0.0/8", "enabled": True, "detail": {"exclusions": ["10.0.0.0/16"]}},
        {"kind": "cloud", "target": "aws:123456789012", "enabled": True},
        {"kind": "application", "target": "local://test-fixture/vulnerable-app", "enabled": True},
    ]


def _connectors():
    return [
        {"kind": "aws", "method": "iam_role", "mode": "passive", "status": "connected",
         "config": {"rate_limit": {"max": 10, "window_seconds": 60}}, "agent_id": "agent-1"},
        {"kind": "network", "method": "api", "mode": "passive", "status": "configured",
         "config": {}},
    ]


def test_resolve_scope_builds_envelope():
    env = resolve_scope(org=_org_row(), scope_entries=_entries(), connectors=_connectors())
    assert env.org_id == "o1"
    assert "10.0.0.0/8" in env.allowed_targets["network"]
    assert env.read_only is True            # all connectors passive
    assert env.exclusions == ("10.0.0.0/16",)
    assert env.rate_limit_max == 10         # most restrictive connector wins
    assert env.scanner == "agent-1"
    assert set(env.allowed_methods) >= {"iam_role", "api"}


def test_resolve_scope_fails_closed_on_empty_scope():
    env = resolve_scope(org=_org_row(), scope_entries=[], connectors=[])
    assert env.allowed_targets == {"network": [], "cloud": [], "application": [], "hardware": []}
    assert not env.target_allowed("anything")
    assert authorize_scope(env, "anything")["reason"] == "target_out_of_scope"


def test_authorize_read_only_blocks_mutation():
    env = resolve_scope(org=_org_row(), scope_entries=_entries(), connectors=_connectors())
    assert authorize_scope(env, "10.9.0.1", kind="network")["allowed"] is True
    assert authorize_scope(env, "10.9.0.1", kind="network", mutating=True)["reason"] == "read_only"
    # outside scope /8 -> denied
    assert authorize_scope(env, "192.168.1.1", kind="network")["reason"] == "target_out_of_scope"


def test_authorize_exclusion():
    env = resolve_scope(org=_org_row(), scope_entries=_entries(), connectors=_connectors())
    assert authorize_scope(env, "10.0.1.5", kind="network")["reason"] == "excluded"  # inside 10.0.0.0/8 and /16


def test_authorize_method_denied():
    env = resolve_scope(org=_org_row(), scope_entries=_entries(), connectors=_connectors())
    assert authorize_scope(env, "10.9.0.1", kind="network", method="ssh")["reason"] == "method_not_allowed"

def test_authorize_maintenance_closed():
    env = resolve_scope(org=_org_row(), scope_entries=_entries(), connectors=_connectors(), maintenance_open=False)
    assert authorize_scope(env, "10.0.0.5", kind="network")["reason"] == "maintenance_window_closed"


def test_active_connector_allows_mutation_with_approval():
    conns = _connectors()
    conns[1]["mode"] = "active"
    env = resolve_scope(org=_org_row(), scope_entries=_entries(), connectors=conns)
    assert env.read_only is False
    assert authorize_scope(env, "10.9.0.1", kind="network", mutating=True)["allowed"] is True

def test_guard_tenant_filters_other_tenant_rows():
    rows = [
        {"id": "a", "tenant": "Acme"},
        {"id": "b", "tenant": "Globex"},
        {"id": "c", "tenant": "Acme"},
        {"id": "d"},  # unmarked reference data — visible to all
    ]
    out = guard_tenant(rows, tenant="Acme")
    assert out["hidden"] == 1          # Globex row hidden
    assert [r["id"] for r in out["kept"]] == ["a", "c", "d"]


def test_guard_tenant_no_tenant_context_no_hiding():
    rows = [{"id": "a", "tenant": "Acme"}, {"id": "b", "tenant": "Globex"}]
    out = guard_tenant(rows, tenant=None)
    assert out["hidden"] == 0
    assert len(out["kept"]) == 2

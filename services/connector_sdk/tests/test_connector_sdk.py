"""Connector SDK tests — context guardrails, redaction, registry, emit."""

from __future__ import annotations

import pytest

from connector_sdk import (
    BaseConnector,
    ConnectorContext,
    Observation,
    RateLimit,
    get_connector,
    register_connector,
    scrub,
)
from connector_sdk.observations import observations_to_json


@pytest.fixture
def context() -> ConnectorContext:
    return ConnectorContext(
        kind="aws", name="aws-prod", method="api",
        config={"region": "eu-west-1", "access_key_id": "AKIAREDACT",
                "secret_access_key": "s3cr3t", "profile": "prod"},
        read_only=True,
        rate_limit=RateLimit(10, 60),
    )


def test_redact_scrubs_secrets(context):
    assert context.redacted_config["secret_access_key"] == "***"
    assert context.redacted_config["access_key_id"] == "***"
    assert context.redacted_config["region"] == "eu-west-1"
    assert "secret" not in repr(context).lower()


def test_guard_read_only_blocks_mutation(context):
    context.guard("10.0.0.1", mutating=False)  # read is fine
    with pytest.raises(PermissionError, match="read-only"):
        context.guard("10.0.0.1", mutating=True)


def test_guard_allowed_methods(context):
    ctx = ConnectorContext(kind="aws", name="x", method="service_principal",
                           allowed_methods=("api",))
    with pytest.raises(PermissionError, match="not allowed"):
        ctx.guard("10.0.0.1")


def test_guard_exclusions_and_maintenance(context):
    ctx = ConnectorContext(kind="network", name="n", method="api",
                           exclusions=("10.0.0.0/8",), maintenance_window_open=False)
    with pytest.raises(PermissionError, match="maintenance"):
        ctx.guard("10.0.0.1")
    ctx2 = ConnectorContext(kind="network", name="n", method="api",
                            exclusions=("10.0.0.0/8",))
    with pytest.raises(PermissionError, match="excluded"):
        ctx2.guard("10.0.0.5")


def test_rate_limit(context):
    for _ in range(10):
        context.rate_limit.allow()
    assert context.rate_limit.allow() is False


class _FakeConnector(BaseConnector):
    kind = "git"
    method = "api"
    mode = "passive"

    def scan(self, context, targets=()):
        return [Observation(asset=t, source="git", observation_type="asset",
                            method="api", confidence="HIGH",
                            evidence={"ref": "HEAD"}, scanner="git_scanner")
                for t in targets]


def test_base_connector_run_honors_guardrails():
    register_connector(_FakeConnector)
    inst = get_connector("git")
    ctx = ConnectorContext(kind="git", name="repo", method="api", read_only=True)
    obs = inst.run(ctx, ["repo-a", "repo-b"])
    assert len(obs) == 2
    assert obs[0].asset == "repo-a"
    assert obs[0].scanner == "git_scanner"

    # mutating run on a passive connector is refused
    with pytest.raises(PermissionError, match="mode="):
        inst.run(ctx, ["repo-a"], mutating=True)


def test_emit_json_roundtrip():
    out = observations_to_json([Observation(asset="a", source="s", observation_type="t")])
    assert '"asset": "a"' in out

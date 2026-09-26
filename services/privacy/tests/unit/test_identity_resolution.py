"""Universal Asset Identity Resolution tests (spec #1)."""

from __future__ import annotations

from privacy.identity import (
    AssetObservation,
    infer_asset_type,
    resolve_identities,
)


def test_same_hostname_merges_across_network_and_agent():
    # network scan sees the host by name; agent sees the same host by fqdn
    obs = [
        AssetObservation("network", {"hostname": "payment-prod-01", "ip": "10.10.1.20"}),
        AssetObservation("agent", {"hostname": "payment-prod-01", "agent_id": "agent-7"}),
    ]
    r = resolve_identities(obs)
    # both collapse to ONE asset
    assert len(r.assets) == 1, r.assets
    asset = r.assets[0]
    assert asset["sources"] == ["agent", "network"]
    assert asset["id"] == "10.10.1.20"
    assert "payment-prod-01" in asset["aliases"]
    assert "agent-7" in asset["aliases"]
    assert r.merges == 1


def test_ip_equals_hostname_only_merges_with_shared_anchor():
    # an IP-only observation and a serial-only observation do NOT share any id,
    # so they are two distinct assets until something links them
    obs = [
        AssetObservation("network", {"ip": "10.10.1.20"}),
        AssetObservation("hardware", {"serial": "Server-009"}),
    ]
    r = resolve_identities(obs)
    assert len(r.assets) == 2, r.assets


def test_chain_resolves_through_intermediate_observation():
    # net(ip only) + agent(hostname+ip) + hardware(serial+hostname)
    # => all three collapse through the intermediate agent observation
    obs = [
        AssetObservation("network", {"ip": "10.10.1.20"}),
        AssetObservation("agent", {"hostname": "pay01", "ip": "10.10.1.20"}),
        AssetObservation("hardware", {"serial": "Server-009", "hostname": "pay01"}),
    ]
    r = resolve_identities(obs)
    assert len(r.assets) == 1, r.assets
    assert r.merges == 2
    a = r.assets[0]
    assert a["sources"] == ["agent", "hardware", "network"]
    assert "10.10.1.20" in a["aliases"]
    assert "server-009" in a["aliases"]


def test_normalizes_case_and_delimiter():
    obs = [
        AssetObservation("hardware", {"serial": "Server-009"}),
        AssetObservation("hardware", {"serial": "server-009"}),
    ]
    r = resolve_identities(obs)
    assert len(r.assets) == 1, r.assets


def test_mac_normalization_merges_delimited_forms():
    obs = [
        AssetObservation("network", {"mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.1"}),
        AssetObservation("network", {"mac": "aabbccddeeff", "ip": "10.0.0.2"}),
    ]
    r = resolve_identities(obs)
    assert len(r.assets) == 1, r.assets


def test_infer_asset_type():
    assert infer_asset_type("network") == "system"
    assert infer_asset_type("cloud") == "cloud_resource"
    assert infer_asset_type("hardware") == "hardware"


def test_distinct_assets_do_not_merge():
    obs = [
        AssetObservation("network", {"ip": "10.1.1.1"}),
        AssetObservation("network", {"ip": "10.1.1.2"}),
    ]
    r = resolve_identities(obs)
    assert len(r.assets) == 2
    assert r.merges == 0

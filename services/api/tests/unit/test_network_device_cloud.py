"""Device crypto surface (§14) and cloud endpoint correlation (§21).

Both are *declaration* sources, and the point of these tests is that a
declaration never becomes an observation:

* a device export cannot smuggle a credential into the evidence store;
* a device is read-only — no write path exists;
* a cloud listener policy is ``NETWORK_CONFIGURED`` until a handshake matches it;
* an unobserved endpoint stays ``UNKNOWN``, and declared/observed drift is a
  review item rather than an automatic correction.
"""

from __future__ import annotations

import pytest

from api.security.network_cloud import correlate as correlate_cloud
from test_network_protocol_safety import client as client  # noqa: F401
from api.security.network_cloud import policy_floor
from network_scanner.inventory.network_devices import (
    UnsafeDeviceRecord,
    build_device_evidence,
    summarize_devices,
    to_device_cbom_assets,
    validate_device,
)


def _firewall() -> dict:
    return {
        "name": "fw-edge-01",
        "role": "FIREWALL",
        "vendor": "paloalto",
        "model": "PA-5220",
        "management_ip": "10.0.0.2",
        "management": {
            "telnet": {"enabled": True},
            "ssh": {"host_key": "ssh-rsa", "kex": ["diffie-hellman-group1-sha1"]},
            "https": {"tls_version": "TLSv1.0", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
            "snmp": {"snmp": {"version": "v2c"}},
        },
        "tls_profiles": [
            {"name": "web", "tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
        ],
        "vpn": [
            {
                "name": "branch",
                "encryption": "3DES",
                "integrity": "HMAC-SHA1",
                "dh_group": "MODP-1024",
            }
        ],
    }


# --------------------------------------------------------------------------- #
# §14 — device crypto surface
# --------------------------------------------------------------------------- #


def test_device_export_becomes_one_record_per_surface():
    records = build_device_evidence(_firewall())
    protocols = [record["protocol"] for record in records]
    assert protocols == ["TELNET", "SSH", "TLS", "SNMP", "TLS", "IPsec"]
    assert {record["device"]["plane"] for record in records} == {"MANAGEMENT", "DATA", "VPN"}
    # an export is a declaration: nothing here was negotiated with the device
    assert all(record["evidence_type"] == "NETWORK_CONFIGURED" for record in records)
    assert all(record["read_only"] is True for record in records)


def test_device_surfaces_are_flagged_for_management_plane_exposure():
    summary = summarize_devices(build_device_evidence(_firewall()))
    issues = summary["issues"]
    assert issues["DEVICE_TELNET_MANAGEMENT_ENABLED"] == 1
    assert issues["DEVICE_LEGACY_SNMP"] == 1
    assert issues["DEVICE_LEGACY_ADMIN_TLS"] == 1
    assert issues["DEVICE_LEGACY_SSH_ALGORITHM"] == 1
    assert issues["DEVICE_WEAK_VPN_ENCRYPTION"] == 1
    assert summary["telnet_devices"] == ["fw-edge-01"]
    assert summary["read_only"] is True
    assert summary["configuration_changes"] == 0


def test_device_records_carry_no_credentials():
    with pytest.raises(UnsafeDeviceRecord) as excinfo:
        build_device_evidence({"name": "sw-1", "management": {"ssh": {"password": "hunter2"}}})
    assert "credential" in str(excinfo.value)

    # nested inside a list is the same failure, not a bypass
    with pytest.raises(UnsafeDeviceRecord):
        validate_device({"name": "sw-1", "vpn": [{"name": "t", "psk": "abc"}]})

    # an SNMP community string is a secret even though it looks like config
    with pytest.raises(UnsafeDeviceRecord):
        validate_device({"name": "sw-1", "management": {"snmp": {"snmp_community": "public"}}})


def test_device_cbom_keeps_planes_apart():
    cbom = to_device_cbom_assets(build_device_evidence(_firewall()))
    roles = {asset["role"] for asset in cbom["assets"]}
    assert "device-management-crypto" in roles
    assert "device-data-plane-crypto" in roles
    assert "device-vpn-crypto" in roles
    assert all(asset["layer"] == "NETWORK_DEVICE" for asset in cbom["assets"])


def test_device_inventory_endpoint_rejects_secrets_and_never_writes(client):
    http, _session = client
    response = http.post(
        "/api/v1/network/device-inventory",
        json={"devices": [{"name": "sw-1", "management": {"ssh": {"enable_secret": "x"}}}]},
    )
    assert response.status_code == 422
    assert "credential" in response.text

    ok = http.post("/api/v1/network/device-inventory", json={"devices": [_firewall()]})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["read_only"] is True
    assert body["configuration_changes"] == 0
    assert body["stored"] == 6
    assert body["summary"]["devices"] == 1
    assert body["evidence_chain"]["appended"] == 6


# --------------------------------------------------------------------------- #
# §21 — cloud network endpoints
# --------------------------------------------------------------------------- #

_CLOUD = [
    {
        "provider": "AWS",
        "type": "LOAD_BALANCER",
        "name": "payments-alb",
        "dns_name": "payments.bank.example",
        "scheme": "internet-facing",
        "backend_protocol": "HTTP",
        "listeners": [
            {
                "port": 443,
                "protocol": "HTTPS",
                "tls_policy": "ELBSecurityPolicy-TLS-1-2-2017-01",
                "certificate_arn": "arn:aws:acm:...:certificate/abc",
            }
        ],
    },
    {
        "provider": "AWS",
        "type": "API_GATEWAY",
        "name": "payments-api",
        "dns_name": "api.bank.example",
        "minimum_tls_version": "TLS_1_0",
    },
    {
        "provider": "AZURE",
        "type": "PRIVATE_ENDPOINT",
        "name": "pe-storage",
        "service": "Microsoft.Storage",
    },
]


def test_cloud_policy_names_map_to_a_declared_floor():
    assert policy_floor("ELBSecurityPolicy-TLS13-1-2-2021-06") == ("TLSv1.3", False)
    assert policy_floor("ELBSecurityPolicy-TLS-1-2-2017-01") == ("TLSv1.2", False)
    assert policy_floor("ELBSecurityPolicy-TLS-1-0-2015-04") == ("TLSv1.0", True)
    assert policy_floor(None) == (None, False)


def test_cloud_declarations_never_become_observations():
    report = correlate_cloud(_CLOUD, [])
    listener = next(item for item in report["endpoints"] if item["kind"] == "LOAD_BALANCER")
    assert listener["evidence_type"] == "UNKNOWN"
    assert listener["declared"]["declared_floor"] == "TLSv1.2"
    assert "no handshake observed" in listener["note"]
    assert report["summary"]["observed_endpoints"] == 0
    assert report["governance"]["cloud_api_calls"] == 0
    assert report["governance"]["read_only"] is True


def test_cloud_listener_flags_public_and_plaintext_origin():
    report = correlate_cloud(_CLOUD, [])
    listener = next(item for item in report["endpoints"] if item["kind"] == "LOAD_BALANCER")
    assert "CLOUD_INTERNET_FACING_LISTENER" in listener["issues"]
    assert "CLOUD_ORIGIN_LEG_MAY_BE_PLAINTEXT" in listener["issues"]
    assert any("CLOUD_GATEWAY_MIN_TLS_LEGACY" == issue for issue in report["issues"])
    assert report["summary"]["internet_facing"] == 1


def test_cloud_observation_that_disagrees_with_the_declaration_is_drift():
    report = correlate_cloud(
        _CLOUD,
        [
            {
                "evidence_type": "NETWORK_ACTIVE_OBSERVED",
                "evidence_id": "ev-cloud",
                "protocol": "TLS",
                "target": {"endpoint": "payments.bank.example:443", "host": "payments.bank.example"},
                "tls_version": "TLSv1.0",
                "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            }
        ],
    )
    listener = next(item for item in report["endpoints"] if item["kind"] == "LOAD_BALANCER")
    assert listener["observed"] is True
    assert listener["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert listener["drift"] == "DIFFERS"
    assert report["drift"][0]["declared"] == "TLSv1.2"
    assert report["drift"][0]["observed"] == "TLSv1.0"
    assert report["summary"]["observed_endpoints"] == 1


def test_cloud_correlation_endpoint_reports_sources(client):
    http, _session = client
    response = http.post("/api/v1/network/cloud-correlate", json={"resources": _CLOUD})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"] == "cryptoscan.cloud-endpoint-correlation/1"
    assert body["sources"]["resources_supplied"] == 3
    assert body["summary"]["private_endpoints"] == 1
    assert body["governance"]["write_operations"] == 0

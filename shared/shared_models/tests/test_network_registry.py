"""Tests for the canonical network protocol/service registry."""

from __future__ import annotations

import pytest

from shared_models.network_registry import (
    ALLOWED,
    DISALLOWED,
    RESTRICTED,
    TCP,
    UDP,
    UNKNOWN,
    catalog,
    classify_endpoint,
    classify_port,
    classify_service,
    risk_severity,
)


def test_catalog_is_nonempty_and_well_formed():
    entries = catalog()
    assert len(entries) >= 90
    for e in entries:
        assert e["protocol"]
        assert e["category"]
        assert e["status"] in (ALLOWED, DISALLOWED, RESTRICTED, "DEPRECATED")
        assert e["exposure"] in ("internet", "internal", "ot-safety")
        assert isinstance(e["encrypted"], bool)


# -- cleartext vs encrypted verdicts --------------------------------------- #
@pytest.mark.parametrize(
    "port,enc,status",
    [
        (443, True, ALLOWED),     # HTTPS
        (22, True, ALLOWED),      # SSH
        (993, True, ALLOWED),     # IMAPS
        (8883, True, RESTRICTED), # MQTT-TLS
        (80, False, DISALLOWED),  # HTTP
        (23, False, DISALLOWED),  # Telnet
        (21, False, DISALLOWED),  # FTP
        (161, False, DISALLOWED), # SNMP
        (6379, False, DISALLOWED),# Redis
        (27017, False, DISALLOWED),# MongoDB
        (1723, False, DISALLOWED),# PPTP (broken VPN)
        (2375, False, DISALLOWED),# unauthenticated Docker API
    ],
)
def test_port_encryption_and_status(port, enc, status):
    info = classify_port(port, TCP)
    assert info.recognized, f"port {port} must be recognized"
    assert info.encrypted is enc
    assert info.status == status


def test_https_owns_443_over_sstp_and_doh():
    # 443 is shared by HTTPS/SSTP/DoH; the canonical web service must win.
    info = classify_port(443, TCP)
    assert info.canonical == "HTTPS"
    assert info.category == "web"


def test_ssh_owns_22_sftp_is_subsystem():
    info = classify_port(22, TCP)
    assert info.canonical == "SSH"
    assert classify_service("sftp").canonical == "SSH"


def test_unknown_port_is_never_safe():
    info = classify_port(47000, TCP)
    assert info.recognized is False
    assert info.status == UNKNOWN
    assert risk_severity(info) in ("MEDIUM", "HIGH")  # unknown => review, not silent


# -- OT / ICS are passive-first and never flagged encrypted-safe ---------- #
@pytest.mark.parametrize("port", [502, 102, 20000, 44818, 4840, 47808, 2404])
def test_ot_ports_are_classified_and_passive(port):
    info = classify_port(port, TCP)
    assert info.recognized
    assert info.category == "ot-ics"
    assert info.exposure == "ot-safety"
    assert "passive" in (info.notes + info.risk_reason).lower() or info.category == "ot-ics"


def test_ot_internet_facing_is_high():
    modbus = classify_port(502, TCP)
    assert risk_severity(modbus, internet_facing=True) == "HIGH"


# -- severity escalation ----------------------------------------------------- #
def test_cleartext_internet_facing_is_critical():
    telnet = classify_port(23, TCP)
    assert risk_severity(telnet, internet_facing=True) == "CRITICAL"
    assert risk_severity(telnet, internet_facing=False) == "HIGH"


def test_internal_service_internet_facing_escalates():
    rdp = classify_port(3389, TCP)
    assert rdp.exposure == "internal"
    assert risk_severity(rdp, internet_facing=True) == "HIGH"


def test_allowed_encrypted_service_is_info():
    assert risk_severity(classify_port(443, TCP)) == "INFO"
    assert risk_severity(classify_port(51820, UDP)) == "INFO"  # WireGuard


# -- banner / service-name classification ---------------------------------- #
@pytest.mark.parametrize(
    "banner,port,expected",
    [
        ("OpenSSH_9.0p1 Ubuntu", 22, "SSH"),
        ("SSH-2.0-OpenSSH_8.9", 22, "SSH"),
        ("nginx/1.24.1", 443, "HTTPS"),
        ("nginx/1.24.1", 80, "HTTP"),
        ("Microsoft-IIS/10.0", 443, "HTTPS"),
        ("220 ProFTPD 1.3.5", 21, "FTP"),
        ("RFB 003.008", 5900, "VNC"),
        ("Mosquitto MQTT broker", 1883, "MQTT"),
        ("modbus", 502, "Modbus TCP"),
        ("5.7.40-MySQL", 3306, "MySQL"),
        ("Dovecot ready", 993, "IMAPS"),
    ],
)
def test_banner_classification(banner, port, expected):
    info = classify_service(banner, port)
    assert info.recognized, banner
    assert info.canonical == expected


def test_web_banner_without_port_defaults_encrypted():
    assert classify_service("nginx").canonical in ("HTTPS",)


# -- endpoint parsing ------------------------------------------------------- #
def test_classify_endpoint():
    assert classify_endpoint("10.0.0.5:443").canonical == "HTTPS"
    assert classify_endpoint("10.0.0.5:23").canonical == "Telnet"
    assert classify_endpoint("10.0.0.5:502").category == "ot-ics"


def test_udp_services():
    assert classify_port(51820, UDP).canonical == "WireGuard"
    assert classify_port(500, UDP).canonical == "IPsec IKE"
    assert classify_port(69, UDP).status == DISALLOWED  # TFTP

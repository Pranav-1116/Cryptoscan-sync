"""Shared fixtures for the universal vendor scanner test suite."""

from __future__ import annotations

import pytest

from universal_vendor.plugins import build_registry


@pytest.fixture()
def registry():
    return build_registry()


@pytest.fixture()
def cisco_context() -> dict:
    return {
        "banner": "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
                  "Version 15.2(7)E9, RELEASE SOFTWARE",
        "config": """crypto key generate rsa modulus 2048
ip ssh version 2
ip ssh server algorithm encryption aes256-gcm aes128-gcm
ip ssh server algorithm kex ecdh-sha2-nistp256
ip ssh server algorithm mac hmac-sha2-256
crypto pki trustpoint ROOT-CA
 enrollment url http://pki.example.com
crypto pki certificate chain ROOT-CA
""",
        "version": "15.2(7)E9",
    }


@pytest.fixture()
def panos_context() -> dict:
    return {
        "banner": "Palo Alto Networks PAN-OS",
        "config": """set system service ssh ciphers aes256-gcm
set network profiles tls-profile tlsp web-server min-version tlsv1-2
set shared certificate default certname paloalto.crt
""",
        "version": "10.2.3",
    }

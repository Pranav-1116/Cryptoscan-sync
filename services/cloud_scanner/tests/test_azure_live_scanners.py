from types import SimpleNamespace

from cloud_scanner.azure.scanners import (
    scan_app_gateway,
    scan_front_door,
    scan_key_vault,
    scan_sql,
    scan_storage,
)
from cloud_scanner.common.compliance_checker import issues_of, summary


class _Vault:
    name = "paykv"
    id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/paykv"
    location = "eastus"


class _KeyClient:
    def list_properties_of_keys(self):
        return [SimpleNamespace(name="cmk")]

    def get_key(self, name):
        inner = SimpleNamespace(kty="RSA", n=int("1" * 2048, 2), key_ops=["encrypt", "decrypt"])
        return SimpleNamespace(name=name, key=inner, properties=SimpleNamespace(enabled=True))


class _Storage:
    class storage_accounts:
        @staticmethod
        def list():
            return [
                SimpleNamespace(
                    name="openstore",
                    enable_https_traffic_only=False,
                    encryption=SimpleNamespace(services=SimpleNamespace(blob=SimpleNamespace(enabled=True))),
                ),
                SimpleNamespace(
                    name="plain",
                    enable_https_traffic_only=True,
                    encryption=SimpleNamespace(services=SimpleNamespace(blob=SimpleNamespace(enabled=False))),
                ),
            ]


def test_azure_key_vault_and_keys():
    findings = scan_key_vault([_Vault()], subscription="sub-1", key_client_factory=lambda url: _KeyClient())
    types = {row["source"]["type"] for row in findings}
    assert "AZURE_KEY_VAULT" in types
    keys = [row for row in findings if row["source"]["type"] == "AZURE_KEY_VAULT_KEY"]
    assert keys
    assert keys[0]["algorithm"] == "RSA"
    assert keys[0]["key_size"] == 2048


def test_azure_storage_flags_https_and_encryption():
    findings = scan_storage(_Storage(), subscription="sub-1")
    issues = {row.get("compliance_issue") for row in findings}
    assert "NO_HTTPS_ONLY" in issues
    assert "NO_ENCRYPTION" in issues


def test_azure_sql_tde_off():
    findings = scan_sql(
        [{"name": "paydb", "transparent_data_encryption_enabled": False}],
        subscription="sub-1",
    )
    assert findings[0]["compliance_issue"] == "NO_ENCRYPTION_AT_REST"


def test_azure_gateway_and_front_door_weak_tls():
    gw = scan_app_gateway(
        [SimpleNamespace(name="web", ssl_policy=SimpleNamespace(min_protocol_version="TLSv1_0"))],
        subscription="sub-1",
    )
    fd = scan_front_door([{"name": "edge", "min_tls_version": "1.0"}], subscription="sub-1")
    assert gw[0]["compliance_issue"] == "WEAK_TLS_VERSION"
    assert fd[0]["source"]["type"] == "AZURE_FRONT_DOOR"
    assert fd[0]["compliance_issue"] == "WEAK_TLS_VERSION"
    flagged = issues_of(gw + fd)
    assert summary(flagged)["issues"] >= 2

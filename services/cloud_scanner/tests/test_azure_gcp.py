from cloud_scanner.core.scanner import CloudScanner
from cloud_scanner.iac.arm import parse_arm
from cloud_scanner.iac.terraform import parse_terraform


def test_arm_flags_key_vault_and_storage(tmp_path):
    path = tmp_path / "azuredeploy.json"
    path.write_text(
        """
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {"type": "Microsoft.KeyVault/vaults/keys", "name": "kv/k", "properties": {"kty": "RSA", "keySize": 2048}},
    {"type": "Microsoft.Storage/storageAccounts", "name": "logs", "properties": {"supportsHttpsTrafficOnly": false}}
  ]
}
"""
    )
    findings = parse_arm(path)
    types = {row["source"]["type"] for row in findings}
    assert "AZURE_KEY_VAULT_KEY" in types
    assert any(row.get("compliance_issue") for row in findings)


def test_terraform_azure_and_gcp_ssl(tmp_path):
    path = tmp_path / "cloud.tf"
    path.write_text(
        """
resource "azurerm_key_vault_key" "k" {
  key_type = "RSA"
  key_size = 2048
}
resource "azurerm_storage_account" "s" {
  https_traffic_only_enabled = false
}
resource "google_compute_ssl_policy" "legacy" {
  min_tls_version = "TLS_1_0"
}
resource "google_storage_bucket" "b" {
  name = "b"
}
"""
    )
    findings = parse_terraform(path)
    issues = {row.get("compliance_issue") for row in findings if row.get("compliance_issue")}
    assert "WEAK_TLS_VERSION" in issues
    assert "NO_HTTPS_ONLY" in issues or "NO_ENCRYPTION" in issues
    assert any(row["metadata"]["cloud_provider"] == "AZURE" for row in findings)
    assert any(row["metadata"]["cloud_provider"] == "GCP" for row in findings)


def test_cloud_scanner_picks_up_arm(tmp_path):
    (tmp_path / "azure-keyvault.json").write_text(
        '{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",'
        '"resources":[{"type":"Microsoft.KeyVault/vaults/keys","name":"k","properties":{"kty":"RSA"}}]}'
    )
    result = CloudScanner(live=False).scan_filesystem(tmp_path)
    types = {row["source"]["type"] for row in result["findings"]}
    assert "AZURE_KEY_VAULT_KEY" in types

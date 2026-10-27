"""Per-category plugin behavior tests across all 16 categories."""

from __future__ import annotations

import pytest

from universal_vendor.models import (
    AssetType,
    CryptoType,
    VendorCategory,
    Visibility,
)
from universal_vendor.registry import UnknownPluginError


def _run_plugin(registry, plugin_id, context, mode="DEEP_DISCOVERY"):
    from universal_vendor.models import ScanMode
    from universal_vendor.scan_modes import UniversalVendorScanner

    return UniversalVendorScanner(registry=registry).run(
        context, scan_id="t", plugin_id=plugin_id, mode=ScanMode(mode),
    )


def _obs(report):
    return report.observations


# ── network ────────────────────────────────────────────────────────────

def test_cisco_reuses_real_parser(registry, cisco_context):
    report = _run_plugin(registry, "cisco_ios_xe", cisco_context,
                         mode="DEEP_DISCOVERY")
    assert report.plugin_id == "cisco_ios_xe"
    assert _obs(report)
    algorithms = {o.algorithm for o in _obs(report) if o.crypto_type == "algorithm"}
    assert algorithms & {"AES", "AES-256-GCM", "AES128-GCM", "AES256-GCM"}
    assert any(o.crypto_type == "certificate" for o in _obs(report))


def test_juniper(registry):
    ctx = {"banner": "Juniper Networks JUNOS 22.4R1",
           "config": "set security ike proposal p1 encryption aes-256-cbc\n"
                     "set security ssh ciphers aes128-cbc"}
    report = _run_plugin(registry, "juniper_junos", ctx)
    assert _obs(report)


def test_mikrotik(registry):
    ctx = {"banner": "MikroTik RouterOS 7.11", "config": "/ip ssh set strong-crypto=yes"}
    report = _run_plugin(registry, "mikrotik_routeros", ctx)
    assert _obs(report)


# ── firewall ───────────────────────────────────────────────────────────

def test_palo_alto(registry, panos_context):
    report = _run_plugin(registry, "paloalto_panos", panos_context)
    assert _obs(report)
    assert all(o.vendor == "Palo Alto" for o in _obs(report))


def test_fortinet(registry):
    ctx = {"banner": "FortiOS 7.4.1", "config": "config system global\n set admin-ssh-cipher AES256-GCM\nend"}
    report = _run_plugin(registry, "fortinet_fortios", ctx)
    assert _obs(report)


def test_checkpoint(registry):
    ctx = {"banner": "Check Point Gaia", "config": "set ssh enabled true\nset ike encryption aes256"}
    report = _run_plugin(registry, "checkpoint_gaia", ctx)
    assert _obs(report)


# ── load balancer ──────────────────────────────────────────────────────

def test_f5_bigip(registry):
    ctx = {"banner": "F5 BIG-IP 17.1.1", "config": "ltm profile client-ssl ssl-client\nltm certificate server.crt"}
    report = _run_plugin(registry, "f5_bigip", ctx)
    assert _obs(report)
    assert any(o.asset_type == AssetType.LOAD_BALANCER.value for o in _obs(report))


def test_nginx(registry):
    ctx = {"server_header": "nginx/1.24.0",
           "config": "listen 443 ssl;\nssl_ciphers HIGH:!aNULL;\nssl_certificate server.crt;"}
    report = _run_plugin(registry, "nginx", ctx)
    assert _obs(report)


# ── cloud ──────────────────────────────────────────────────────────────

def test_aws_kms_metadata_only(registry):
    ctx = {
        "api_metadata": {
            "keys": [
                {"key_id": "arn:aws:kms:us-east-1:123:key/abc",
                 "algorithm": "SYMMETRIC_DEFAULT", "key_size": 256,
                 "state": "Enabled", "rotation_period": "365d"},
            ],
            "certificates": [
                {"arn": "arn:aws:acm:us-east-1:123:certificate/x",
                 "type": "managed", "signature_algorithm": "SHA256WITHRSA"},
            ],
        },
        "region": "us-east-1",
    }
    report = _run_plugin(registry, "aws", ctx)
    obs = _obs(report)
    assert obs
    assert all(o.visibility == Visibility.API_VISIBLE.value for o in obs)
    keys = [o for o in obs if o.crypto_type == "key"]
    assert keys and keys[0].key_size == 256


def test_azure_key_vault(registry):
    ctx = {"api_metadata": {
        "keys": [{"name": "vault-key", "algorithm": "RSA", "key_size": 2048,
                  "state": "enabled"}]}}
    report = _run_plugin(registry, "microsoft_azure", ctx)
    assert _obs(report)


def test_gcp_cloud_kms(registry):
    ctx = {"api_metadata": {
        "keys": [{"key_id": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                  "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}]}}
    report = _run_plugin(registry, "google_cloud", ctx)
    assert _obs(report)


# ── PKI ────────────────────────────────────────────────────────────────

def test_vault_pki(registry):
    ctx = {"config": "vault secrets enable pki\n"
                     "vault write pki/root/generate/internal key_type=rsa key_bits=4096\n"
                     "vault write pki/issue/web key_type=ec key_bits=256",
           "api_metadata": "ca_chain present"}
    report = _run_plugin(registry, "hashicorp_vault_pki", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.asset_type == AssetType.CA.value for o in obs)
    assert any(o.key_size == 4096 for o in obs)


def test_adcs(registry):
    ctx = {"banner": "Microsoft Active Directory Certificate Services",
           "config": "KeyLength=4096\nHashAlgorithm=SHA256\nCA=EnterpriseRoot"}
    report = _run_plugin(registry, "microsoft_adcs", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.key_size == 4096 for o in obs)


def test_openssl_pki(registry):
    ctx = {"config": "openssl.cnf: default_bits = 2048\ndefault_md = sha256\n"
                     "dir = /etc/pki"}
    report = _run_plugin(registry, "openssl_internal_pki", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.key_size == 2048 for o in obs)


# ── HSM metadata-only ──────────────────────────────────────────────────

def test_hsm_metadata_only_never_extracts_keys(registry):
    ctx = {"banner": "Thales Luna Network HSM 7.4", "model": "Luna K7",
           "firmware": "7.4.2", "slots": 2,
           "config": "algorithms: RSA, ECDSA, AES, ML-KEM-768"}
    report = _run_plugin(registry, "thales_luna", ctx)
    obs = _obs(report)
    assert obs
    assert all(o.asset_type == AssetType.HSM.value for o in obs)
    # never any key material in any observation output
    dumped = [o.model_dump(mode="json") for o in obs]
    assert all("private_key" not in str(d) and "master_key" not in str(d)
               for d in dumped)


def test_hsm_rejects_key_material(registry):
    from universal_vendor.plugins.hsm import ThalesLunaPlugin

    plugin = ThalesLunaPlugin()
    with pytest.raises(AssertionError):
        plugin.normalize({
            "vendor": "Thales", "product": "Luna HSM", "asset_id": "hsm",
            "crypto_type": "algorithm", "algorithm": "RSA",
            "private_key": "super-secret-material",
        })


def test_entrust_nshield(registry):
    ctx = {"banner": "Entrust nShield Connect", "model": "nCipher nShield 6000",
           "firmware": "12.60"}
    report = _run_plugin(registry, "entrust_nshield", ctx)
    assert _obs(report)


# ── identity ───────────────────────────────────────────────────────────

def test_keycloak_oidc_metadata(registry):
    ctx = {
        "banner": "Keycloak",
        "oidc_document": {
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "jwks_uri": "https://idp.example.com/realms/x/protocol/openid-connect/certs",
        },
    }
    report = _run_plugin(registry, "keycloak", ctx)
    obs = _obs(report)
    assert obs
    algos = {o.algorithm for o in obs if o.crypto_type == "algorithm"}
    assert {"RS256", "ES256"} <= algos
    assert any(o.asset_type == AssetType.IDENTITY_PROVIDER.value for o in obs)


def test_entra_id(registry):
    ctx = {"banner": "Microsoft Entra ID",
           "oidc_document": '{"id_token_signing_alg_values_supported":["RS256"]}'}
    report = _run_plugin(registry, "microsoft_entra_id", ctx)
    assert _obs(report)


def test_okta(registry):
    ctx = {"banner": "Okta", "config": "signing certificate=okta-signing.pem"}
    report = _run_plugin(registry, "okta", ctx)
    assert _obs(report)


# ── database ───────────────────────────────────────────────────────────

def test_postgresql(registry):
    ctx = {"banner": "PostgreSQL 15.4",
           "config": "ssl = on\nssl_cert_file = /etc/pgsql/server.crt\nencryption = pgcrypto"}
    report = _run_plugin(registry, "postgresql", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.asset_type == AssetType.DATABASE.value for o in obs)
    assert any(o.certificate for o in obs)


def test_mysql(registry):
    ctx = {"banner": "MySQL 8.0.36", "config": "ssl-ca=/etc/mysql/ca.pem\nssl-cert=server.pem"}
    report = _run_plugin(registry, "mysql", ctx)
    assert _obs(report)


def test_redis(registry):
    ctx = {"banner": "Redis 7.0.12", "config": "tls-port 6379\ntls-cert-file /etc/redis/tls/redis.crt"}
    report = _run_plugin(registry, "redis", ctx)
    assert _obs(report)


# ── middleware ─────────────────────────────────────────────────────────

def test_apache_httpd(registry):
    ctx = {"server_header": "Apache/2.4.57 (Ubuntu)",
           "config": "SSLEngine on\nSSLCipherSuite HIGH:!aNULL:!MD5\nSSLProtocol TLSv1.2 TLSv1.3"}
    report = _run_plugin(registry, "apache_httpd", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.protocol == "TLS" for o in obs)


def test_tomcat(registry):
    ctx = {"banner": "Apache Tomcat/9.0.83",
           "config": '<Connector port="8443" keystoreFile="/opt/tomcat/keystore" ciphers="TLS_AES_256_GCM_SHA384"/>'}
    report = _run_plugin(registry, "apache_tomcat", ctx)
    assert _obs(report)


def test_weblogic(registry):
    ctx = {"banner": "Oracle WebLogic Server 12.2.1.4",
           "config": "SSLEnabled=true\nClientCertificateEnforced=true\n"
                     "CipherSuites=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
                     "SSLProtocolVersionRange=TLSv1_2"}
    report = _run_plugin(registry, "oracle_weblogic", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.asset_type == AssetType.MIDDLEWARE.value for o in obs)


# ── OS ─────────────────────────────────────────────────────────────────

def test_rhel_openssl(registry):
    ctx = {"banner": "Red Hat Enterprise Linux 9.3",
           "openssl_version": "OpenSSL 3.0.7",
           "config": "Ciphers aes256-gcm@openssh.com\nCiphers chacha20-poly1305@openssh.com",
           "ssh_config": {"password_auth": "no"}}
    report = _run_plugin(registry, "redhat_rhel", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.asset_type == AssetType.OS.value for o in obs)
    assert any("3.0.7" in str(o.configuration) for o in obs)


def test_windows(registry):
    ctx = {"banner": "Microsoft Windows Server 2022",
           "schannel_ciphers": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]}
    report = _run_plugin(registry, "microsoft_windows", ctx)
    assert _obs(report)


def test_esxi(registry):
    ctx = {"banner": "VMware ESXi 7.0 Update 3",
           "config": "Security.PermitRootLogin = 0"}
    report = _run_plugin(registry, "vmware_esxi", ctx)
    assert _obs(report)


# ── EDR / SIEM as intelligence sources ─────────────────────────────────

def test_edr_intelligence_source(registry):
    ctx = {"banner": "CrowdStrike Falcon",
           "endpoints": [{"hostname": "db-01", "tls": {"version": "1.2"},
                          "certs": ["expired-leaf"]}]}
    report = _run_plugin(registry, "crowdstrike_falcon", ctx)
    obs = _obs(report)
    assert obs
    assert all(o.asset_type == AssetType.EDR.value for o in obs)
    assert any("db-01" in (o.asset_id or "") for o in obs)


def test_siem_passive_crypto_intelligence(registry):
    ctx = {"banner": "Splunk Enterprise Security",
           "events": [{"asset_id": "fw-edge", "event_type": "tls",
                       "detail": "TLS 1.0 handshake from client"},
                      {"asset_id": "vpn-gw", "event_type": "cert",
                       "detail": "certificate expired"}]}
    report = _run_plugin(registry, "splunk_esi", ctx)
    obs = _obs(report)
    assert obs
    assert all(o.asset_type == AssetType.SIEM.value for o in obs)
    # SIEM is passive: no behavior analytics, only crypto intelligence
    assert all(o.crypto_type in (CryptoType.CONFIGURATION.value, "siem-event")
               for o in obs)


def test_qradar(registry):
    ctx = {"banner": "IBM QRadar",
           "events": [{"asset_id": "web-01", "detail": "TLS 1.0 observed"}]}
    report = _run_plugin(registry, "ibm_qradar", ctx)
    assert _obs(report)


# ── DevOps ─────────────────────────────────────────────────────────────

def test_github_repo_dependencies(registry):
    ctx = {"api_metadata": {
        "dependencies": [
            {"repo": "org/app", "library": "openssl", "version": "1.1.1",
             "algorithm": "AES-256-GCM"},
            {"repo": "org/app", "library": "bouncycastle", "version": "1.78",
             "algorithm": "ECDSA"},
        ],
        "iac": [{"repo": "org/infra", "file": "kms.tf",
                 "algorithm": "aws_kms_key"}]}}
    report = _run_plugin(registry, "github", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.vendor == "GitHub" for o in obs)


def test_gitlab(registry):
    ctx = {"api_metadata": {"dependencies": [{"repo": "g/group/proj",
                                              "library": "libsodium"}]}}
    report = _run_plugin(registry, "gitlab", ctx)
    assert _obs(report)


# ── containers / registries ────────────────────────────────────────────

def test_docker_registry_images(registry):
    ctx = {"api_metadata": {"images": [
        {"name": "app/api", "tag": "1.4.2", "digest": "sha256:ab12",
         "base_image": "node:20-bookworm"},
    ], "signing": {"cosign": "enabled"}}}
    report = _run_plugin(registry, "docker_engine", ctx)
    obs = _obs(report)
    assert obs
    assert any("app/api" in (o.asset_id or "") for o in obs)
    assert any(o.asset_type == AssetType.CONTAINER.value for o in obs)


def test_ecr(registry):
    ctx = {"api_metadata": {"images": [{"name": "repo/web", "tag": "latest"}]}}
    report = _run_plugin(registry, "aws_ecr", ctx)
    assert _obs(report)


def test_harbor(registry):
    ctx = {"api_metadata": {"images": [{"name": "harbor.local/library/app"}]}}
    report = _run_plugin(registry, "harbor", ctx)
    assert _obs(report)


# ── kubernetes core + adapters ─────────────────────────────────────────

def test_kubernetes_core(registry):
    ctx = {"kubeconfig": "clusters: k8s",
           "config": "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt "
                     "--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt "
                     "--service-account-signing-key-file=/etc/kubernetes/pki/sa.key"}
    report = _run_plugin(registry, "kubernetes", ctx)
    obs = _obs(report)
    assert obs
    assert any(o.asset_type == AssetType.KUBERNETES.value for o in obs)
    assert any("kube-apiserver" in str(o.configuration) for o in obs)


def test_eks_adapter_not_separate_system(registry):
    ctx = {"kubeconfig": "clusters: eks-cluster-1",
           "eks_version": "1.30", "cmk_arn": "arn:aws:kms:...",
           "config": "--tls-cert-file=/var/lib/kubelet/pki/kubelet.crt"}
    report = _run_plugin(registry, "aws_eks", ctx)
    obs = _obs(report)
    assert obs
    # adapter still emits kubernetes-core observations + provider metadata
    assert any(o.asset_type == AssetType.KUBERNETES.value for o in obs)
    assert any(o.configuration and o.configuration.get("provider") == "AWS"
               for o in obs)


def test_aks_gke_openshift_rancher(registry):
    for plugin_id, ctx in [
        ("azure_aks", {"kubeconfig": "aks-cluster", "aks_version": "1.29",
                       "key_vault_id": "/subscriptions/x"}),
        ("google_gke", {"kubeconfig": "gke-cluster", "gke_version": "1.30",
                        "cmek_key": "projects/p/.../cryptoKeys/k"}),
        ("openshift", {"kubeconfig": "ocp", "openshift_version": "4.14",
                       "config": "ingresscontroller default servingCertificate"}),
        ("rancher", {"kubeconfig": "rancher", "rancher_version": "2.9",
                     "cluster_ids": ["c-1", "c-2"]}),
    ]:
        report = _run_plugin(registry, plugin_id, ctx)
        assert _obs(report), f"{plugin_id} produced no observations"


# ── SaaS honesty ───────────────────────────────────────────────────────

def test_salesforce_api_visible(registry):
    ctx = {"banner": "Salesforce",
           "certificate": {"type": "custom", "name": "web-cert",
                           "expires": "2027-01-01"},
           "tls_ciphers": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]}
    report = _run_plugin(registry, "salesforce", ctx)
    obs = _obs(report)
    assert obs
    assert all(o.visibility == Visibility.API_VISIBLE.value for o in obs)


def test_saas_never_overclaims(registry):
    # SaaS with no exposed crypto API → honest NOT_SUPPORTED
    report = _run_plugin(registry, "saas_not_supported", {"banner": "Some SaaS"})
    obs = _obs(report)
    assert obs
    assert all(o.visibility == Visibility.NOT_SUPPORTED.value for o in obs)
    # NOT_SUPPORTED is a discovery outcome, never fabricated findings
    assert all(o.crypto_type == "configuration" for o in obs)


def test_unknown_plugin_id_rejected(registry):
    with pytest.raises(UnknownPluginError):
        _run_plugin(registry, "no_such_plugin", {})


def test_scrub_secrets():
    from universal_vendor.plugin import scrub_secrets

    data = {"password": "hunter2", "nested": {"api_key": "xyz", "keep": 1},
            "list": [{"token": "abc"}, {"ok": True}]}
    scrubbed = scrub_secrets(data)
    assert scrubbed["password"] == "<REDACTED>"
    assert scrubbed["nested"]["api_key"] == "<REDACTED>"
    assert scrubbed["nested"]["keep"] == 1
    assert scrubbed["list"][0]["token"] == "<REDACTED>"
    assert scrubbed["list"][1]["ok"] is True

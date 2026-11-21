"""The estate graph read as the migration twin — a small Meridian-shaped estate.

The graph is written the way the sandbox agents write it: SYSTEM ← part_of ← HOST,
services that run on the host and expose endpoints, a library inside a package, a served
certificate issued by the bank CA, an HSM the payment host uses, the platform server, and
vendors with asset-register contract states.
"""

from __future__ import annotations

from datetime import datetime, timezone

from agility.estate_migration_twin import migration_context, twin_from_estate
from agility.migration_simulation import simulate_migration

NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


class _Estate:
    def __init__(self) -> None:
        self.assets: list[dict] = []
        self.edges: list[dict] = []
        self.evidence: list[dict] = []

    def asset(self, asset_id, kind, name, identity=None, **attributes):
        self.assets.append({"asset_id": asset_id, "type": kind, "name": name,
                            "identity": identity or {"name": name}, "attributes": attributes,
                            "environment": "production-sandbox"})
        return asset_id

    def fact(self, target, evidence_type="RUNTIME_OBSERVED", **facts):
        evidence_id = f"ev-{len(self.evidence) + 1}"
        self.evidence.append({"evidence_id": evidence_id, "target": target,
                              "evidence_type": evidence_type, "facts": facts, "layer": "PLATFORM"})
        return evidence_id

    def edge(self, subject, predicate, obj, basis="RUNTIME_OBSERVATION"):
        self.edges.append({"subject": subject, "predicate": predicate, "object": obj, "basis": basis,
                           "evidence_ids": [self.fact(subject, relationship=predicate)]})


def _meridian() -> _Estate:
    e = _Estate()
    swift = e.asset("sys-swift", "SYSTEM", "SWIFT Gateway", owner="Payments Operations", criticality="tier-0")
    core = e.asset("sys-core", "SYSTEM", "Core Banking", owner="Core Banking Platform", criticality="tier-0")
    hsm_sys = e.asset("sys-hsm", "SYSTEM", "Payment HSM", owner="Payments Security")
    branch = e.asset("sys-branch", "SYSTEM", "Branch Banking", criticality="tier-2")

    gw = e.asset("host-gw", "HOST", "swift-gateway", {"hostname": "swift-gateway.bank.sandbox",
                                                      "ip_address": "10.210.0.4"})
    db = e.asset("host-db", "HOST", "core-banking-db", {"hostname": "core-banking-db.bank.sandbox",
                                                        "ip_address": "10.210.0.7"})
    hsm_host = e.asset("host-hsm", "HOST", "hsm-sim", {"hostname": "hsm-sim.bank.sandbox",
                                                       "ip_address": "10.210.0.6"})
    legacy = e.asset("host-legacy", "HOST", "legacy-branch", {"hostname": "legacy-branch.bank.sandbox",
                                                              "ip_address": "10.210.0.5"})
    for host, system in ((gw, swift), (db, core), (hsm_host, hsm_sys), (legacy, branch)):
        e.edge(host, "part_of", system, basis="APPROVED_MAPPING")

    # SWIFT gateway: nginx exposes a TLS 1.3 endpoint with an RSA-3072 certificate
    nginx = e.asset("svc-nginx-gw", "SERVICE", "nginx", {"name": "nginx", "host": "swift-gateway"})
    e.edge(nginx, "runs_on", gw)
    ep = e.asset("ep-gw-443", "NETWORK_ENDPOINT", "swift-gateway:443/https",
                 {"host": "0.0.0.0", "port": "443", "protocol": "tls"})
    e.edge(nginx, "exposes", ep)
    e.fact(ep, "NETWORK_ACTIVE_OBSERVED", protocol="TLSv1.3", algorithm="TLS_AES_256_GCM_SHA384",
           role="negotiated-cipher-suite")
    cert = e.asset("cert-gw", "CERTIFICATE", "swift-gateway.bank.sandbox",
                   {"fingerprint_sha256": "aa" * 32}, issuer="CN=Meridian Bank Issuing CA",
                   not_after="2027-01-10T00:00:00+00:00", public_key_algorithm="RSA")
    e.fact(cert, "CERTIFICATE_OBSERVED", algorithm="RSA", key_size=3072, role="certificate-public-key")
    e.fact(cert, "CERTIFICATE_OBSERVED", algorithm="SHA256withRSA", role="certificate-signature")
    e.edge(ep, "uses_certificate", cert, basis="NETWORK_OBSERVATION")
    ca = e.asset("ca-meridian", "CA", "Meridian Bank Issuing CA", {"subject": "CN=Meridian Bank Issuing CA"})
    e.edge(cert, "issued_by", ca)
    pkg = e.asset("pkg-libssl", "PACKAGE", "libssl3", {"name": "libssl3", "version": "3.3.2", "ecosystem": "apk"})
    e.edge(pkg, "part_of", gw, basis="DEPLOYMENT_CONFIG")
    lib = e.asset("lib-openssl", "LIBRARY", "OpenSSL 3.3.2", {"name": "OpenSSL", "version": "3.3.2"},
                  family="OpenSSL", version="3.3.2")
    e.fact(lib, "STATIC_OBSERVED", supported_algorithms=["TLSv1.3", "RSA", "ECDSA", "X25519", "AES-GCM"])
    e.edge(lib, "part_of", pkg, basis="DEPLOYMENT_CONFIG")
    e.edge(nginx, "uses_crypto_library", lib)

    # vendors (with the asset register's contract states)
    openssl_v = e.asset("v-openssl", "VENDOR", "OpenSSL Software Foundation · OpenSSL",
                        {"name": "OpenSSL Software Foundation", "product": "OpenSSL"},
                        vendor="OpenSSL Software Foundation", product="OpenSSL", contract_state="ACTIVE")
    e.fact(openssl_v, "VENDOR_DECLARED", product="OpenSSL", version="3.3.2", pqc_ready=False)
    e.edge(lib, "provided_by", openssl_v, basis="DEPLOYMENT_CONFIG")
    alpine = e.asset("v-alpine", "VENDOR", "Alpine Linux · Alpine Linux (operating system)",
                     {"name": "Alpine Linux", "product": "Alpine Linux (operating system)"},
                     vendor="Alpine Linux", product="Alpine Linux (operating system)",
                     contract_state="NONE_ON_RECORD")
    e.fact(alpine, "VENDOR_DECLARED", product="Alpine Linux", version="3.20")
    e.edge(gw, "provided_by", alpine)
    # the platform server — and its maker, who takes no part in an algorithm change
    server = e.asset("hw-gw", "HARDWARE", "VMware7,1 virtual platform",
                     {"serial_number": "VMware-42"}, manufacturer="VMware, Inc.", model="VMware7,1")
    e.fact(server, "STATIC_OBSERVED", supported_algorithms=["AES-NI", "SHA-NI"])
    e.edge(gw, "hosted_on", server)
    vmware = e.asset("v-vmware", "VENDOR", "VMware · VMware7,1", {"name": "VMware", "product": "VMware7,1"},
                     vendor="VMware", product="VMware7,1", contract_state="ACTIVE")
    e.edge(server, "provided_by", vmware)

    # the payment HSM: the gateway's host uses it; it reports its key slots
    hsm = e.asset("hsm-0", "HSM", "payShield-10K-sim",
                  {"vendor": "Meridian-Sim", "serial_number": "SBX-HSM-0001", "partition": "payments"},
                  firmware="v3.4.1-sandbox", fips_mode=False)
    e.fact(hsm, key_slots=[{"slot": 0, "algorithm": "AES-256"}, {"slot": 1, "algorithm": "3DES-112"}])
    e.edge(hsm_host, "uses_hsm", hsm)

    # core banking DB, which the gateway reaches over the network (observed, by IP)
    pg = e.asset("db-core", "DATABASE", "core-banking-ledger",
                 {"host": "10.210.0.7", "port": "5432", "engine": "postgresql"})
    e.edge(pg, "hosted_on", db)
    peer = e.asset("remote-core", "NETWORK_ENDPOINT", "10.210.0.7:5432",
                   {"host": "10.210.0.7", "port": "5432", "protocol": "tcp"})
    e.edge(nginx, "connects_to", peer)
    # the CMDB-declared architecture
    e.edge(swift, "depends_on", hsm_sys, basis="APPROVED_MAPPING")
    e.edge(branch, "depends_on", core, basis="APPROVED_MAPPING")

    # legacy branch: TLS 1.0 with an RSA-1024 certificate
    lep = e.asset("ep-legacy", "NETWORK_ENDPOINT", "legacy-branch:443",
                  {"host": "10.210.0.5", "port": "443", "protocol": "tls"})
    e.edge(lep, "hosted_on", legacy)
    e.fact(lep, "NETWORK_ACTIVE_OBSERVED", protocol="TLSv1", algorithm="AES128-SHA",
           role="negotiated-cipher-suite")
    lcert = e.asset("cert-legacy", "CERTIFICATE", "legacy-branch", {"fingerprint_sha256": "bb" * 32},
                    public_key_algorithm="RSA")
    e.fact(lcert, "CERTIFICATE_OBSERVED", algorithm="RSA", key_size=1024, role="certificate-public-key")
    e.edge(lep, "uses_certificate", lcert, basis="NETWORK_OBSERVATION")

    # a certificate observed by a scan that no system claims
    stray = e.asset("cert-stray", "CERTIFICATE", "old-vpn.example", {"fingerprint_sha256": "cc" * 32})
    e.fact(stray, "CERTIFICATE_OBSERVED", algorithm="RSA", key_size=2048, role="certificate-public-key")
    return e


def _twin():
    e = _meridian()
    return twin_from_estate(e.assets, e.edges, e.evidence, estate="meridian-bank", now=NOW)


def test_members_follow_evidenced_edges_only():
    twin = _twin()
    by_id = {a["asset_id"]: a for a in twin["assets"]}
    assert by_id["cert-gw"]["system_ids"] == ["sys-swift"]
    assert by_id["lib-openssl"]["system_ids"] == ["sys-swift"]
    assert by_id["hsm-0"]["system_ids"] == ["sys-hsm"]
    assert by_id["cert-legacy"]["system_ids"] == ["sys-branch"]
    # nobody claims the stray certificate, and it is not guessed into a system
    assert by_id["cert-stray"]["system_ids"] == []
    systems = {s["name"]: s for s in twin["systems"]}
    assert systems["SWIFT Gateway"]["criticality"] == "critical"
    assert systems["SWIFT Gateway"]["hosts"] == ["swift-gateway"]


def test_connections_from_declared_and_observed_edges():
    deps = {(d["source"], d["target"], d["type"]) for d in _twin()["dependencies"]}
    assert ("sys-swift", "sys-hsm", "depends_on") in deps            # CMDB-declared
    assert ("sys-branch", "sys-core", "depends_on") in deps
    assert ("sys-swift", "sys-core", "connects_to") in deps          # observed, by exact IP


def test_capability_lists_are_never_use_and_hardware_makers_are_not_migration_vendors():
    twin = _twin()
    algorithms = {row["algorithm"] for row in twin["evidence"]}
    assert "AES-NI" not in algorithms and "X25519" not in algorithms
    assert twin["library_catalog"]["OpenSSL 3.3.2"]["algorithms"][:2] == ["TLSv1.3", "RSA"]
    swift_vendors = {row["vendor_id"] for row in twin["system_vendors"] if row["system_id"] == "sys-swift"}
    assert "vendor:openssl software foundation" in swift_vendors
    assert "vendor:alpine linux" in swift_vendors
    assert "vendor:vmware" not in swift_vendors
    assert twin["platform_hardware"]["sys-swift"][0]["vendors"] == ["VMware"]


def test_rsa_to_mlkem_on_the_bank_estate():
    result = simulate_migration(_twin(), from_algo="RSA", to_algo="ML-KEM-768", now=NOW)
    assert result["twin_context"]["kind"] == "ESTATE_GRAPH"
    systems = {s["name"]: s for s in result["systems"]}
    assert set(systems) == {"SWIFT Gateway", "Branch Banking"}
    swift = systems["SWIFT Gateway"]
    codes = {f["code"] for f in swift["findings"]}
    assert {"LIBRARY_LACKS_TARGET", "VENDOR_RELEASE_NOT_READY", "CERTIFICATES_TO_REISSUE",
            "VENDOR_CAPABILITY_UNKNOWN", "VENDOR_NO_SUPPORT_CONTRACT", "PEER_OUTSIDE_CHANGE"} <= codes
    # the VM is listed as the platform and never blocks
    assert swift["twin"]["platform"][0]["model"] == "VMware7,1"
    assert "HARDWARE_CANNOT_RUN_TARGET" not in codes
    peers = {c["name"] for c in swift["twin"]["connections"]}
    assert {"Payment HSM", "Core Banking"} <= peers
    branch = systems["Branch Banking"]
    assert any(f["code"] == "TLS_VERSION_TOO_OLD" for f in branch["findings"])
    assert result["strategy"]["recommended"] == "PARALLEL"
    assert any("1 twin asset(s)" in u and "linked to no system" in u for u in result["unknowns"])


def test_3des_reaches_the_payment_hsm():
    result = simulate_migration(_twin(), from_algo="3DES", to_algo="AES-256-GCM", now=NOW)
    systems = {s["name"]: s for s in result["systems"]}
    assert set(systems) == {"Payment HSM"}
    hsm = systems["Payment HSM"]["twin"]["hardware"]
    assert hsm and hsm[0]["kind"] == "HSM" and hsm[0]["holds_affected_keys"] is True
    # no mechanism list was collected from the HSM: unknown, never a pass
    assert hsm[0]["target_support"] == "UNKNOWN"
    assert any(f["code"] == "HARDWARE_CAPABILITY_UNKNOWN" for f in systems["Payment HSM"]["findings"])


def test_context_for_the_form():
    ctx = migration_context(_twin())
    systems = {s["name"]: s for s in ctx["systems"]}
    assert systems["SWIFT Gateway"]["certificates"] == 1
    assert systems["SWIFT Gateway"]["servers"] == 1
    assert systems["Payment HSM"]["hsms"] == 1
    rsa = next(a for a in ctx["algorithms"] if a["algorithm"] == "RSA")
    assert rsa["systems"] == ["Branch Banking", "SWIFT Gateway"]
    assert ctx["unowned_algorithms"] == {"RSA": 1}


def test_pure_and_deterministic():
    e = _meridian()
    snapshot = repr((e.assets, e.edges, e.evidence))
    first = twin_from_estate(e.assets, e.edges, e.evidence, now=NOW)
    second = twin_from_estate(e.assets, e.edges, e.evidence, now=NOW)
    assert first == second
    assert repr((e.assets, e.edges, e.evidence)) == snapshot

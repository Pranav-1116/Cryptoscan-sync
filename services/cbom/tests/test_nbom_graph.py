"""NBOM as a network projection — the review's twenty-two points, as tests."""

from __future__ import annotations

import pytest
from cbom import nbom_graph as n
from cbom import techbom as tb

EVID = "EVID-92821"
NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

def aes(name: str = "AES-256-GCM", *, evidence_type: str = "CONFIGURED") -> dict:
    return tb.asset("CRYPTO_ASSET", name, evidence_ids=[EVID], algorithm="AES",
                    key_size=256, evidence_type=evidence_type)


def suite(name: str = "TLS_AES_256_GCM_SHA384") -> dict:
    return n.cipher_suite(name=name, tls_version="TLS1.3", kex="X25519",
                          auth="ECDSA-P256", bulk="AES-256-GCM", mac="SHA-384",
                          evidence_ids=[EVID])


def endpoint(port: int = 443, host: str = "10.10.10.20", **fields) -> dict:
    return n.endpoint(host=host, port=port, evidence_ids=[EVID], **fields)


def routing_estate() -> dict:
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID])
    application = n.service_of(name="Payments API", kind="APPLICATION",
                               evidence_ids=[EVID])
    service = n.service_of(name="payments-api", port=8080, evidence_ids=[EVID])
    public = endpoint(name="payments.bank.example:443", sni=["payments.bank.example"])
    return n.estate(
        n.routed(endpoint_row=public, service_row=service, basis="sni-header",
                 evidence_ids=[EVID], observed_at=NOW, first_seen=EARLIER, last_seen=NOW,
                 protocol="TCP", port=443),
        n.serves(application_row=application, service_row=service, system_row=system,
                 evidence_ids=[EVID]),
        estate_id="payments")


# --------------------------------------------------------------------------- #
# 1–2. An address is a location; the identity is the node behind it
# --------------------------------------------------------------------------- #

def test_an_endpoint_needs_a_host_and_a_port():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.endpoint(host="10.10.10.20", port=None, evidence_ids=[EVID])
    assert refused.value.code == "ENDPOINT_WITHOUT_HOST_OR_PORT"


def test_a_port_that_is_not_a_port_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.endpoint(host="10.10.10.20", port="https", evidence_ids=[EVID])
    assert refused.value.code == "ENDPOINT_PORT_NOT_A_PORT"


def test_two_virtual_hosts_on_one_address_are_two_endpoints():
    shared = {"host": "10.10.10.20", "port": 443, "sni": ["a.bank.example"],
              "evidence_ids": [EVID]}
    second = {**shared, "sni": ["b.bank.example"]}
    left = n.endpoint(name="a.bank.example:443", **shared)
    right = n.endpoint(name="b.bank.example:443", **second)
    assert left["key"] != right["key"]
    assert left["attributes"]["host"] == right["attributes"]["host"] == "10.10.10.20"


def test_a_stable_id_does_not_move_when_the_estate_renumbers():
    row = endpoint(name="payments.bank.example:443")
    before = n.stable_id(row)
    bom = n.build(routing_estate())
    rebuilt = next(item for item in bom["endpoints"]
                   if item["name"] == "payments.bank.example:443")
    assert n.stable_id(rebuilt) == before
    assert rebuilt["id"].startswith("TECH-EP-")


def test_the_chain_from_an_endpoint_reaches_the_business_system():
    bom = n.build(routing_estate())
    chain = bom["chains"]["payments.bank.example:443"]
    assert [band for band, rows in chain["levels"].items() if rows] == [
        "service", "application", "system"]


def test_a_name_match_is_not_a_routing_basis():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.routed(endpoint_row=endpoint(), service_row=n.service_of(name="x",
                                                                   evidence_ids=[EVID]),
                 basis="name-match", evidence_ids=[EVID])
    assert refused.value.code == "ROUTING_BASIS_NOT_EVIDENCE"


def test_every_routing_basis_is_a_classified_basis():
    review = {"dns-resolution", "sni-header", "deployment-metadata", "kubernetes-ingress",
              "api-gateway-config", "load-balancer-config", "service-registry",
              "runtime-observation"}
    assert review <= set(tb.BASES)


# --------------------------------------------------------------------------- #
# 3. Three TLS boundaries, three graphs
# --------------------------------------------------------------------------- #

def _front(*, certificate: bool = True) -> dict:
    tls = {"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"}
    if certificate:
        tls["certificate"] = "CERT-001"
    return n.endpoint(host="10.0.0.1", port=443, name="front:443", tls=tls,
                      evidence_ids=[EVID])


def test_termination_plaintext_upstream_re_encryption_and_passthrough():
    plain = n.endpoint(host="10.0.0.2", port=80, name="back:80", transport="PLAIN",
                       evidence_ids=[EVID])
    secure = n.endpoint(host="10.0.0.3", port=443, name="back:443",
                        tls={"version": "TLS1.2"}, evidence_ids=[EVID])
    terminate = n.tls_hop(frontend=_front(), backend=plain, mode="TERMINATE",
                          evidence_ids=[EVID])
    re_encrypt = n.tls_hop(frontend=_front(), backend=secure, mode="RE_ENCRYPT",
                           evidence_ids=[EVID])
    passthrough = n.tls_hop(frontend=_front(certificate=False), backend=secure,
                            mode="PASSTHROUGH", evidence_ids=[EVID])
    assert {row["claims"][0]["relation"] for row in (terminate, re_encrypt, passthrough)} \
        == {"TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH"}


def test_termination_with_a_tls_upstream_is_refused_as_a_re_encryption():
    secure = n.endpoint(host="10.0.0.3", port=443, tls={"version": "TLS1.2"},
                        evidence_ids=[EVID])
    with pytest.raises(tb.ClaimRefused) as refused:
        n.tls_hop(frontend=_front(), backend=secure, mode="TERMINATE",
                  evidence_ids=[EVID])
    assert refused.value.code == "TERMINATION_WITH_TLS_UPSTREAM"


def test_re_encryption_without_upstream_tls_is_refused():
    plain = n.endpoint(host="10.0.0.2", port=80, transport="PLAIN", evidence_ids=[EVID])
    with pytest.raises(tb.ClaimRefused) as refused:
        n.tls_hop(frontend=_front(), backend=plain, mode="RE_ENCRYPT",
                  evidence_ids=[EVID])
    assert refused.value.code == "RE_ENCRYPT_WITHOUT_UPSTREAM_TLS"


def test_a_passthrough_may_not_present_a_certificate():
    secure = n.endpoint(host="10.0.0.3", port=443, tls={"version": "TLS1.2"},
                        evidence_ids=[EVID])
    certificate = n.certificate(name="CERT-001", subject="CN=front", evidence_ids=[EVID])
    with pytest.raises(tb.ClaimRefused) as refused:
        n.tls_hop(frontend=_front(certificate=False), backend=secure,
                  mode="PASSTHROUGH", certificate=certificate, evidence_ids=[EVID])
    assert refused.value.code == "PASSTHROUGH_WITH_CERTIFICATE"


def test_a_mode_is_one_of_three():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.tls_hop(frontend=_front(), backend=_front(), mode="OFFLOAD",
                  evidence_ids=[EVID])
    assert refused.value.code == "UNKNOWN_TLS_MODE"


# --------------------------------------------------------------------------- #
# 4. The certificate chain
# --------------------------------------------------------------------------- #

def test_a_certificate_is_five_edges_not_one_row():
    certificate = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                                signature_algorithm="ECDSA-SHA256", evidence_ids=[EVID])
    key_algorithm = n.algorithm(name="ECDSA P-256", family="ECDSA", curve="P-256",
                                key_size=256, evidence_ids=[EVID])
    key = n.public_key(name="KEY-CERT-001", key_algorithm_row=key_algorithm,
                       curve="P-256", evidence_ids=[EVID])
    signature = n.algorithm(name="ECDSA-SHA256", family="ECDSA", hash_name="SHA-256",
                            evidence_ids=[EVID])
    issuer = n.authority(name="Intermediate CA", evidence_ids=[EVID])
    root = n.authority(name="Root CA", kind="ROOT", evidence_ids=[EVID])
    chain = n.certificate_chain(certificate_row=certificate, key_row=key,
                                key_algorithm_row=key_algorithm,
                                signature_algorithm_row=signature, issuer_row=issuer,
                                root_row=root, evidence_ids=[EVID])
    bom = n.build(n.estate(chain, estate_id="chain"))
    assert bom["refusals"] == []
    assert {claim["relation"] for claim in bom["claims"]} == {
        "CONTAINS_KEY", "USES_ALGORITHM", "SIGNED_WITH", "ISSUED_BY", "SIGNED_BY"}


# --------------------------------------------------------------------------- #
# 5–6. A suite is four dependencies, and supported is not negotiated
# --------------------------------------------------------------------------- #

def test_a_cipher_suite_is_decomposed_into_four_crypto_assets():
    # the suite was read off a handshake, so its parts are NETWORK_OBSERVED (review 6/7)
    rows = {"bulk": aes(evidence_type="NETWORK_OBSERVED"),
            "mac": tb.asset("CRYPTO_ASSET", "SHA-384", evidence_ids=[EVID],
                            algorithm="SHA", evidence_type="NETWORK_OBSERVED"),
            "kex": tb.asset("CRYPTO_ASSET", "X25519", evidence_ids=[EVID],
                            evidence_type="NETWORK_OBSERVED"),
            "auth": tb.asset("CRYPTO_ASSET", "ECDSA-P256", evidence_ids=[EVID],
                             evidence_type="NETWORK_OBSERVED")}
    part = n.suite_parts(suite_row=suite(), parts=rows, evidence_ids=[EVID])
    bom = n.build(n.estate(part, estate_id="suite"))
    assert bom["refusals"] == []
    roles = {claim["facts"]["role"] for claim in bom["claims"]}
    assert roles == {"bulk", "mac", "kex", "auth"}


def test_supported_is_not_negotiated():
    public = endpoint(name="payments.bank.example:443")
    chosen, allowed = suite(), suite("TLS_AES_128_GCM_SHA256")
    part = n.merge(n.negotiated(endpoint_row=public, suite_row=chosen,
                                evidence_ids=[EVID], observed_at=NOW),
                   n.supported(endpoint_row=public, suite_rows=[chosen, allowed],
                               evidence_ids=[EVID]))
    bom = n.build(n.estate(part, estate_id="tls"))
    view = n.negotiated_crypto(bom, query=public["name"])
    assert [row["name"] for row in view["negotiated"]] == ["TLS_AES_256_GCM_SHA384"]
    assert [row["name"] for row in view["supported_only"]] == ["TLS_AES_128_GCM_SHA256"]


def test_a_capability_list_cannot_claim_a_negotiation():
    bom = n.build(n.estate({"assets": [endpoint(name="front:443"), suite()],
                            "claims": [tb.claim("front:443", "NEGOTIATES",
                                                "TLS_AES_256_GCM_SHA384",
                                                basis="capability-list",
                                                evidence_ids=[EVID])]},
                           estate_id="floor"))
    assert [row["code"] for row in bom["refusals"]] == [
        "CLAIM_WEAKER_THAN_RELATION_REQUIRES"]


def test_a_configuration_file_cannot_claim_a_session():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.negotiated(endpoint_row=endpoint(name="front:443"), suite_row=suite(),
                     basis="config-parse", evidence_ids=[EVID])
    assert refused.value.code == "NEGOTIATION_NEEDS_A_HANDSHAKE"


# --------------------------------------------------------------------------- #
# 7. Runtime is not the network
# --------------------------------------------------------------------------- #

def test_the_process_carries_runtime_crypto_the_network_never_saw():
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVID])
    process = tb.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID], pid=1821)
    library = tb.asset("CRYPTO_LIBRARY", "OpenSSL 3.0.13", evidence_ids=[EVID])
    runtime_aes = aes("AES-128-CBC", evidence_type="RUNTIME_OBSERVED")
    bom = n.build(n.estate(n.runtime(process_row=process, application_row=application,
                                     library_row=library, crypto_rows=[runtime_aes],
                                     evidence_ids=[EVID]), estate_id="runtime"))
    assert bom["refusals"] == []
    assert {claim["confidence"] for claim in bom["claims"]} == {"RUNTIME_OBSERVED"}
    assert tb.RUNTIME_OBSERVED in tb.PROVEN and tb.RUNTIME_OBSERVED != tb.NETWORK_OBSERVED


def test_a_runtime_asset_cannot_be_evidenced_by_a_configuration_file():
    bom = n.build(n.estate({"assets": [
        tb.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID]),
        aes("AES-128-CBC", evidence_type="RUNTIME_OBSERVED")],
        "claims": [tb.claim("payments-api[1821]", "USES_CRYPTO", "AES-128-CBC",
                            basis="config-parse", evidence_ids=[EVID])]},
        estate_id="mismatch"))
    assert [row["code"] for row in bom["refusals"]] == ["EVIDENCE_CLASS_MISMATCH"]


# --------------------------------------------------------------------------- #
# 8. Keys are references
# --------------------------------------------------------------------------- #

def test_a_key_reference_carries_metadata_and_no_material():
    row = n.key_reference(name="KEY-REF-8271", key_ref="arn:key/8271", purpose="SIGN",
                          algorithm="RSA", key_size=2048, holder="HSM-001",
                          evidence_ids=[EVID])
    assert row["attributes"]["key_ref"] == "arn:key/8271"
    assert row["attributes"]["key_size"] == 2048


def test_key_material_is_refused_by_name():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.key_reference(name="K", key_ref="arn:k", purpose="SIGN", algorithm="RSA",
                        private_key="MIIEvQIBADANBg", evidence_ids=[EVID])
    assert refused.value.code == "KEY_MATERIAL_REFUSED"


def test_a_pem_in_a_fact_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.key_reference(name="K", key_ref="arn:k", purpose="SIGN", algorithm="RSA",
                        note="-----BEGIN PRIVATE KEY-----", evidence_ids=[EVID])
    assert refused.value.code == "KEY_MATERIAL_REFUSED"


def test_the_application_reaches_its_hsm_through_an_operation():
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVID])
    hsm = tb.asset("HSM", "HSM-001", evidence_ids=[EVID])
    key = n.key_reference(name="KEY-REF-8271", key_ref="arn:key/8271", purpose="SIGN",
                          algorithm="RSA", evidence_ids=[EVID])
    capability = tb.asset("CRYPTO_CAPABILITY", "RSA-2048 signing", evidence_ids=[EVID])
    part = n.key_use(application_row=application, hsm_row=hsm, key_row=key,
                     capability_row=capability, operation="SIGN", evidence_ids=[EVID])
    bom = n.build(n.estate(part, estate_id="keys"))
    assert {claim["relation"] for claim in bom["claims"]} == {
        "USES_HSM", "HOLDS_KEY", "USES_KEY", "PERFORMS"}


# --------------------------------------------------------------------------- #
# 9. TLS in transit is not TDE at rest
# --------------------------------------------------------------------------- #

def test_database_tls_and_tde_are_reported_separately():
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVID])
    database = tb.asset("DATABASE", "DB-01", evidence_ids=[EVID])
    listener = n.endpoint(host="10.20.0.5", port=5432, name="db-01:5432", evidence_ids=[EVID])
    part = n.database_dependency(application_row=application, database_row=database,
                                 endpoint_row=listener, tls_suite=suite(),
                                 tde={"algorithm": "AES-256-XTS", "enabled": True},
                                 evidence_ids=[EVID])
    block = part["database_crypto"]["DB-01"]
    assert block["in_transit"] != block["at_rest"] and block["distinct"] is True
    bom = n.build(n.estate(part, estate_id="db"))
    assert any(claim["relation"] == "NEGOTIATES" and claim["facts"]["port"] == 5432
               for claim in bom["claims"])


# --------------------------------------------------------------------------- #
# 10–12. The sidecar holds the certificate; the WAF protects
# --------------------------------------------------------------------------- #

def test_the_sidecar_proxies_the_application_and_holds_the_certificate():
    mesh_device = tb.asset("SERVICE_MESH", "MESH-01", evidence_ids=[EVID])
    sidecar = tb.asset("PROCESS", "envoy-sidecar", evidence_ids=[EVID])
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVID])
    certificate = n.certificate(name="CERT-MESH-001", subject="spiffe://payments",
                                evidence_ids=[EVID])
    part = n.mesh(mesh_row=mesh_device, trust_domain="bank.internal",
                  sidecars=[sidecar], proxied=[application], certificate_row=certificate,
                  evidence_ids=[EVID])
    bom = n.build(n.estate(part, estate_id="mesh"))
    users = {claim["from_kind"] if "from_kind" in claim else
             bom["by_key"][claim["from_key"]]["kind"]
             for claim in bom["claims"] if claim["relation"] == "USES_CERTIFICATE"}
    assert users == {"PROCESS"}
    assert any(claim["relation"] == "PROXY_FOR" and claim["to"] == "Payments API"
               for claim in bom["claims"])


def test_a_passthrough_hop_naming_a_certificate_is_the_whole_reason_for_the_rule():
    secure = n.endpoint(host="10.0.0.3", port=443, name="back:443",
                        tls={"version": "TLS1.2", "certificate": "CERT-9"},
                        evidence_ids=[EVID])
    with pytest.raises(tb.ClaimRefused) as refused:
        n.tls_hop(frontend=secure, backend=_front(certificate=False),
                  mode="PASSTHROUGH", evidence_ids=[EVID])
    assert refused.value.code == "PASSTHROUGH_WITH_CERTIFICATE"


# --------------------------------------------------------------------------- #
# 13–14. SSH and IPsec negotiate parameters, not versions
# --------------------------------------------------------------------------- #

def test_ssh_negotiates_four_parameters_against_a_host():
    host = tb.asset("HOST", "srv-001", evidence_ids=[EVID])
    listener = n.endpoint(host="10.10.2.11", port=22, name="srv-001:22",
                          transport="SSH", evidence_ids=[EVID])
    ssh = n.ssh_service(
        name="sshd@srv-001", host_row=host, endpoint_row=listener,
        kex=tb.asset("CRYPTO_ASSET", "X25519-kex", evidence_ids=[EVID]),
        host_key=tb.asset("CRYPTO_ASSET", "Ed25519-hostkey", evidence_ids=[EVID]),
        cipher=tb.asset("CRYPTO_ASSET", "ChaCha20-Poly1305-ssh", evidence_ids=[EVID]),
        mac=tb.asset("CRYPTO_ASSET", "HMAC-SHA2-256", evidence_ids=[EVID]),
        evidence_ids=[EVID])
    bom = n.build(n.estate(ssh, estate_id="ssh"))
    roles = {claim["facts"]["role"] for claim in bom["claims"]
             if claim["relation"] == "NEGOTIATES"}
    assert roles == {"kex", "host-key", "cipher", "mac"}
    assert {claim["confidence"] for claim in bom["claims"]
            if claim["relation"] == "NEGOTIATES"} == {"NETWORK_OBSERVED"}
    # the host and its listener were read from the inventory, not from the banner
    assert {claim["confidence"] for claim in bom["claims"]
            if claim["relation"] != "NEGOTIATES"} == {"CONFIGURED"}


def test_a_tunnel_keeps_its_proposals_apart_from_what_it_uses():
    gateway = tb.asset("VPN_GATEWAY", "VPN-GW-01", evidence_ids=[EVID])
    peer = tb.asset("VPN_GATEWAY", "VPN-GW-BRANCH", evidence_ids=[EVID])
    zone = tb.asset("NETWORK_SEGMENT", "Payment Network", evidence_ids=[EVID])
    tunnel = n.ipsec_tunnel(
        name="branch-to-payments", gateway_row=gateway, peer_row=peer, zone_row=zone,
        encryption=tb.asset("CRYPTO_ASSET", "AES-256", evidence_ids=[EVID]),
        integrity=tb.asset("CRYPTO_ASSET", "SHA-256", evidence_ids=[EVID]),
        dh_group=tb.asset("CRYPTO_ASSET", "DH-Group-19", evidence_ids=[EVID]),
        proposals=[tb.asset("CRYPTO_CAPABILITY", "AES-128 proposal",
                            evidence_ids=[EVID])],
        evidence_ids=[EVID])
    bom = n.build(n.estate(tunnel, estate_id="vpn"))
    negotiated = {claim["to"] for claim in bom["claims"]
                  if claim["relation"] == "NEGOTIATES"}
    supported = {claim["to"] for claim in bom["claims"] if claim["relation"] == "SUPPORTS"}
    assert negotiated == {"AES-256", "SHA-256", "DH-Group-19"}
    assert supported == {"AES-128 proposal"} and not supported & negotiated


# --------------------------------------------------------------------------- #
# 15–16. Every edge carries its record
# --------------------------------------------------------------------------- #

def test_every_edge_in_the_projection_carries_its_record():
    bom = n.build(routing_estate())
    edges = n.graph(bom)["edges"]
    assert edges and n.graph(bom)["edges_missing_a_record"] == []
    for edge in edges:
        for field in ("source", "target", "relationship", "basis", "confidence",
                      "evidence_id"):
            assert edge[field], field
    route = next(edge for edge in edges if edge["relationship"] == "ROUTES_TO")
    assert route["port"] == 443 and route["protocol"] == "TCP"
    assert route["first_seen"] == EARLIER and route["last_seen"] == NOW


# --------------------------------------------------------------------------- #
# 17. Lifecycle and drift
# --------------------------------------------------------------------------- #

def test_lifecycle_separates_first_seen_active_and_unknown():
    bom = n.build(routing_estate())
    state = n.lifecycle(bom, reference=NOW)
    assert state["counts"].get("ACTIVE") == 1
    # the two CMDB edges carry no timestamps: unknown is not active
    assert state["counts"].get("UNKNOWN") == 2


def test_an_edge_that_moved_is_superseded_not_removed_and_added():
    before = n.build(routing_estate())
    after_doc = routing_estate()
    for claim in after_doc["claims"]:
        if claim["relation"] == "ROUTES_TO":
            claim["to"] = "payments-api-v2"
    after_doc["assets"].append(n.service_of(name="payments-api-v2", port=8080,
                                            evidence_ids=[EVID]))
    after = n.build(after_doc)
    feed = n.drift(before, after, reference=NOW)
    assert feed["by_change"] == {"EDGE_SUPERSEDED": 1}
    event = feed["events"][0]
    assert event["previous_target"] == "payments-api"
    assert event["target"] == "payments-api-v2"
    assert "crypto_impact" in event


# --------------------------------------------------------------------------- #
# 18–20. Projection, vendor, hardware
# --------------------------------------------------------------------------- #

def test_a_projection_cannot_be_its_own_source():
    bom = n.build(routing_estate())
    with pytest.raises(tb.ClaimRefused) as refused:
        n.from_document(bom)
    assert refused.value.code == "PROJECTION_AS_SOURCE"
    with pytest.raises(ValueError):
        n.build({"schema": tb.SCHEMA, "assets": [], "claims": []})


def test_a_network_device_joins_the_vendor_chain_and_the_firmware():
    part = n.network_device(kind="LOAD_BALANCER", name="LB-01", vendor="F5",
                            product="BIG-IP i5800", model="i5800",
                            firmware_version="17.1.1", evidence_ids=[EVID])
    server = tb.asset("PHYSICAL_SERVER", "SRV-01", evidence_ids=[EVID])
    bom = n.build(n.estate(part, n.on_hardware(device_row=part["assets"][0],
                                               hardware_row=server, evidence_ids=[EVID]),
                           estate_id="vendor"))
    relations = {claim["relation"] for claim in bom["claims"]}
    assert {"HAS_MODEL", "SUPPLIED_BY", "RUNS_FIRMWARE", "RUNS_ON"} <= relations
    assert any(row["kind"] == "VENDOR" and row["name"] == "F5" for row in bom["assets"])


def test_a_device_kind_this_model_does_not_build_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.network_device(kind="ROUTER", name="R-01", vendor="Cisco", product="ASR",
                         evidence_ids=[EVID])
    assert refused.value.code == "NOT_A_NETWORK_DEVICE"


# --------------------------------------------------------------------------- #
# 21–22. Coverage propagates, and the spine exists
# --------------------------------------------------------------------------- #

def test_coverage_is_partial_and_says_so_downstream():
    block = n.coverage(expected=500, observed=420, unavailable=50, unknown=30)
    assert block["verdict"] == "PARTIAL"
    assert set(block["propagates"].values()) == {"PARTIAL"}
    assert block["expected"] == (block["observed"] + block["unavailable"]
                                 + block["unknown"])


def test_coverage_that_does_not_add_up_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        n.coverage(expected=100, observed=80, unavailable=40)
    assert refused.value.code == "COVERAGE_DOES_NOT_RECONCILE"


def test_the_reviews_whole_vocabulary_exists_in_one_graph():
    vocabulary = ("CONNECTS_TO", "ROUTES_TO", "TERMINATES_TLS", "RE_ENCRYPTS",
                  "PASSTHROUGH", "PROTECTS", "AUTHENTICATES", "USES_CERTIFICATE",
                  "USES_HSM", "USES_KMS")
    assert all(relation in tb.RELATIONS for relation in vocabulary)
    assert tb.RELATIONS["PROXY_FOR"]["chain"] == "NETWORK"

"""HBOM as a hardware view of the estate graph — the review's sixteen points, as tests."""

from __future__ import annotations

import pytest
from cbom import hbom_graph as h
from cbom import techbom as tb

EVIDENCE = "EVID-829182"
NOW = "2026-11-03T08:30:00Z"


def ev(identifier: str = EVIDENCE, **fields) -> dict:
    return h.evidence(
        identifier, collector=fields.pop("collector", "linux-hardware-collector"),
        collector_version=fields.pop("collector_version", "1.4.2"),
        target_id=fields.pop("target_id", "BANK-SRV-001"),
        observed_at=fields.pop("observed_at", NOW),
        source=fields.pop("source", "/sys/class/dmi/id"),
        evidence_type=fields.pop("evidence_type", "INVENTORY"),
        raw_reference=fields.pop("raw_reference", "dmi/id/product_serial"),
        normalized_fact=fields.pop("normalized_fact", "serial=SN-1"),
        hash=fields.pop("hash", "sha256:3b1f"), confidence=fields.pop("confidence", "HIGH"),
        **fields)


def firmware_row(status: str = "SUPPORTED", version: str = "8.4.2", **fields) -> dict:
    return h.firmware(f"PaymentHSM firmware {version}", version=version,
                      vendor="SyntheticHSM", product="PaymentHSM-9000",
                      release_date="2025-04-01", status=status, evidence_ids=[EVIDENCE],
                      **fields)


def hsm_part(**fields) -> dict:
    return h.hsm(
        "HSM-001", vendor="SyntheticHSM", product="PaymentHSM-9000",
        model="PaymentHSM-9000", firmware_version=fields.pop("firmware_version", "8.4.2"),
        firmware_release=fields.pop("firmware_release", firmware_row()),
        ha_mode="Active/Active", cluster="HSM-CLUSTER-A",
        members=[{"name": "HSM-002", "role": "active"}],
        partitions=[{"name": "HSM-001-P1", "id": "P1", "key_types": ["RSA"],
                     "applications": ["Payments API"]}],
        capabilities=[{"algorithm": "RSA-2048", "key_types": ["RSA"], "key_sizes": [2048],
                       "operations": ["SIGN"]}],
        key_types=["RSA"], key_sizes=[2048], operations=["SIGN"],
        certificates=["cert:abab"], applications=["Payments API"], systems=["Payments"],
        serial_number="HSM-SN-1", evidence_ids=[EVIDENCE], **fields)


def server_part(**overrides) -> dict:
    spec = {
        "manufacturer": "Dell", "model": "PowerEdge R760", "serial_number": "SN-1",
        "asset_tag": "BANK-SRV-001",
        "cpu": {"model": "Xeon Gold 6430", "cores": 32, "threads": 64,
                "topology": "2 sockets x 16 cores"},
        "memory": {"total_mb": 524288, "modules": 8},
        "motherboard": {"model": "0R760A", "revision": "A02"},
        "bios": {"version": "2.4.1"}, "tpm": {"version": "2.0"},
        "nics": [{"model": "Broadcom 57414", "mac": "aa:bb:cc:00:11:22",
                  "ip": "10.10.1.20", "vlan": "VLAN-40"}],
        "storage": [{"model": "NVMe PM1743", "size_gb": 3840}],
        "raid": {"model": "PERC H755"}, "gpus": [{"model": "L4"}],
        "pci": [{"model": "Crypto PCIe card", "vendor": "SyntheticHSM"}],
        "accelerator": {"model": "SyntheticHSM ACC-8000"},
        "evidence_ids": [EVIDENCE],
    }
    spec.update(overrides)
    return h.server(**spec)


def payments(*parts) -> dict:
    """The review's own estate: an HSM, a server, and the software that uses them."""
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    system = tb.asset("BUSINESS_SYSTEM", "Payments", evidence_ids=[EVIDENCE])
    crypto = tb.asset("CRYPTO_ASSET", "RSA-2048", evidence_ids=[EVIDENCE],
                      evidence_type="RUNTIME_OBSERVED")
    server = server_part()
    host = server["assets"][0]["name"]
    document = h.estate(
        h.merge(hsm_part(), server, h.merge(
            {"assets": [application, system, crypto], "claims": [
                h.claim("Payments", "CONTAINS", "Payments API", basis="cmdb-import",
                        evidence_ids=[EVIDENCE]),
                h.claim("Payments API", "USES_CRYPTO", "CRYPTO_ASSET:RSA-2048:PRODUCTION",
                        basis="runtime-probe", evidence_ids=[EVIDENCE]),
                h.claim("CRYPTO_ASSET:RSA-2048:PRODUCTION", "PROTECTED_BY", "HSM-001",
                        basis="config-parse", evidence_ids=[EVIDENCE]),
                h.claim("Payments API", "RUNS_ON", host, basis="config-parse",
                        evidence_ids=[EVIDENCE]),
            ]})),
        estate_id="bank-estate", environment="PRODUCTION",
        expected={"HSM": 2, "PHYSICAL_SERVER": 1, "CPU": 1},
        gaps=[{"kind": "HSM", "reason": "one HSM collector offline"}])
    return document


# 1 — the device is a tree, with the field set ---------------------------------

def test_a_server_is_a_tree_of_parts_not_one_row():
    bom = h.build(h.estate(server_part()))
    kinds = {row["kind"] for row in bom["assets"]}
    assert {"PHYSICAL_SERVER", "CPU", "MEMORY", "MOTHERBOARD", "BIOS", "TPM", "NIC",
            "STORAGE", "RAID_CONTROLLER", "GPU", "PCI_DEVICE",
            "CRYPTO_ACCELERATOR"} <= kinds
    root = bom["component_tree"][0]
    assert root["kind"] == "PHYSICAL_SERVER"
    assert {"CPU", "BIOS"} <= {child["kind"] for child in root["children"]}


def test_the_declared_field_set_is_reported_including_what_is_missing():
    row = server_part()["assets"][0]
    completeness = row["attributes"]["field_completeness"]
    assert completeness["expected"] == len(h.ASSET_FIELDS)
    assert "part_number" in completeness["missing"]
    assert row["attributes"].get("part_number") is None
    assert row["attributes"]["unknown_fields"]


def test_a_declared_field_supplied_by_the_collector_is_not_listed_as_missing():
    row = server_part(datacenter="DC1", rack="R12", slot="U7")["assets"][0]
    assert {"datacenter", "rack", "slot"} <= set(
        field for field in h.ASSET_FIELDS
        if field not in row["attributes"]["unknown_fields"])


def test_every_hardware_asset_carries_the_field_block():
    bom = h.build(payments())
    for row in bom["assets"]:
        if "asset_id" not in row["attributes"]:
            continue  # a firmware release is a release, not a collected device
        assert "field_completeness" in row["attributes"]
        assert "unknown_fields" in row["attributes"]
        assert row["attributes"]["asset_id"] == row["name"]


# 2 — HSM depth ----------------------------------------------------------------

def test_an_hsm_is_a_device_with_parts_capabilities_and_users():
    bom = h.build(payments())
    kinds = bom["techbom"]["by_kind"]
    assert kinds["HSM"] == 2 and kinds["HSM_CLUSTER"] == 1 and kinds["HSM_PARTITION"] == 1
    relations = {row["relation"] for row in bom["claims"]}
    assert {"MEMBER_OF", "PEERS_WITH", "HAS_PARTITION", "SUPPORTS", "USES_HSM",
            "RUNS_FIRMWARE", "HAS_MODEL", "SUPPLIED_BY"} <= relations


def test_a_capability_lists_key_types_sizes_and_operations():
    bom = h.build(payments())
    capability = next(row for row in bom["assets"]
                      if row["kind"] == "CRYPTO_CAPABILITY")
    attributes = capability["attributes"]
    assert attributes["key_sizes"] == ["2048"]
    assert attributes["operations"] == ["SIGN"]
    assert attributes["algorithm"] == "RSA-2048"


def test_key_material_is_refused_by_name():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                   private_key="MIIEvQIBADANBgkqhkiG9w0")
    assert refused.value.code == "KEY_MATERIAL_REFUSED"
    with pytest.raises(tb.ClaimRefused) as pem:
        h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                   note="-----BEGIN PRIVATE KEY-----")
    assert pem.value.code == "KEY_MATERIAL_REFUSED"


def test_a_key_reference_is_what_a_hardware_collector_may_hand_over():
    row = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                     key_reference="KREF-0007", public_key_sha256="ab" * 32)
    assert row["attributes"]["key_reference"] == "KREF-0007"


# 3 — hardware → software ------------------------------------------------------

def test_a_process_runs_on_the_host_that_carries_the_hardware():
    process = tb.asset("PROCESS", "payments-api", evidence_ids=[EVIDENCE])
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    server = server_part()
    host = server["assets"][0]["name"]
    document = h.estate(h.merge(server, {"assets": [process, application], "claims": [
        h.claim("payments-api", "RUNS_ON", host, basis="process-trace",
                evidence_ids=[EVIDENCE]),
        h.claim("Payments API", "RUNS_ON", host, basis="config-parse",
                evidence_ids=[EVIDENCE]),
        h.claim("Payments API", "USES_HSM", "HSM-001", basis="config-parse",
                evidence_ids=[EVIDENCE]),
    ]}, hsm_part()))
    bom = h.build(document)
    chain = {(row["from"], row["relation"], row["to"]) for row in bom["claims"]}
    assert ("payments-api", "RUNS_ON", host) in chain
    assert ("Payments API", "RUNS_ON", host) in chain
    assert [row for row in bom["refusals"]
            if row["code"] == "TYPE_MISMATCH"] == []


def test_an_application_cannot_be_declared_as_a_component_of_a_server():
    server = server_part()
    host = server["assets"][0]["name"]
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge(server, {"assets": [application], "claims": [
        h.claim(host, "HAS_COMPONENT", "Payments API", basis="agent-inventory",
                evidence_ids=[EVIDENCE])]})))
    codes = [row["code"] for row in bom["refusals"]]
    assert "TYPE_MISMATCH" in codes


# 4 — hardware → crypto: four facts, four relations ----------------------------

def test_supports_performs_uses_and_protected_by_are_separate_facts():
    bom = h.build(payments())
    relations = {(row["relation"], row["confidence"]) for row in bom["claims"]}
    assert ("SUPPORTS", "VENDOR_DECLARED") in relations
    assert all(row["relation"] != "PERFORMS" for row in bom["claims"])


def test_a_datasheet_cannot_say_the_device_performed_an_operation():
    device = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE])
    capability = h.capability("cap RSA", algorithm="RSA-2048", operations=["SIGN"],
                              evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [device, capability], "claims": [
        h.claim(device["name"], "PERFORMS", "cap RSA", basis="vendor-datasheet",
                evidence_ids=[EVIDENCE]),
        h.claim(device["name"], "SUPPORTS", "cap RSA", basis="vendor-datasheet",
                evidence_ids=[EVIDENCE])]})))
    refused = [row for row in bom["refusals"]
               if row["code"] == "CLAIM_WEAKER_THAN_RELATION_REQUIRES"]
    assert len(refused) == 1 and "PERFORMS" in refused[0]["subject"]
    assert [row["relation"] for row in bom["claims"]] == ["SUPPORTS"]


def test_a_capability_claim_can_never_start_at_an_application():
    capability = h.capability("cap RSA", algorithm="RSA-2048", evidence_ids=[EVIDENCE])
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [application, capability], "claims": [
        h.claim("Payments API", "SUPPORTS", "cap RSA", basis="vendor-datasheet",
                evidence_ids=[EVIDENCE])]})))
    assert bom["refusals"][0]["code"] == "TYPE_MISMATCH"


def test_the_crypto_evidence_class_still_governs_an_application_use():
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    crypto = tb.asset("CRYPTO_ASSET", "RSA-2048", evidence_ids=[EVIDENCE],
                      evidence_type="RUNTIME_OBSERVED")
    bom = h.build(h.estate(h.merge({"assets": [application, crypto], "claims": [
        h.claim("Payments API", "USES_CRYPTO", "RSA-2048", basis="sbom-import",
                evidence_ids=[EVIDENCE])]})))
    assert bom["refusals"][0]["code"] == "EVIDENCE_CLASS_MISMATCH"


# 5 — vendor depth -------------------------------------------------------------

def test_the_vendor_chain_reaches_from_product_to_device_to_application():
    bom = h.build(payments())
    edges = {(row["relation"], row["from"], row["to"]) for row in bom["claims"]}
    assert ("HAS_MODEL", "HSM-001", "SyntheticHSM PaymentHSM-9000") in edges
    assert ("SUPPLIED_BY", "SyntheticHSM PaymentHSM-9000", "SyntheticHSM") in edges
    assert ("USES_HSM", "Payments API", "HSM-001") in edges


def test_two_devices_from_one_vendor_share_one_vendor_asset():
    def device(identifier: str, serial: str) -> dict:
        return h.hsm(identifier, vendor="SyntheticHSM", product="PaymentHSM-9000",
                     model="PaymentHSM-9000", serial_number=serial,
                     firmware_version="8.4.2", evidence_ids=[EVIDENCE])

    bom = h.build(h.estate(h.merge(device("HSM-001", "SN-1"),
                                   device("HSM-003", "SN-3"))))
    assert bom["techbom"]["by_kind"]["VENDOR"] == 1
    assert bom["techbom"]["by_kind"]["VENDOR_PRODUCT"] == 1
    assert bom["refusals"] == []


# 6 — network hardware ---------------------------------------------------------

def test_a_firewall_is_hardware_and_forwarding_is_an_evidenced_edge():
    firewall = h.hardware("FIREWALL", manufacturer="Palo Alto", model="PA-5450",
                          firmware_version="11.1.3", evidence_ids=[EVIDENCE],
                          ip="10.10.0.1", vlan="VLAN-10")
    waf = tb.asset("WAF", "edge-waf", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [firewall, waf], "claims": [
        h.claim(firewall["name"], "FORWARDS_TO", "edge-waf", basis="api-poll",
                evidence_ids=[EVIDENCE])]})))
    assert bom["counts"]["FIREWALL"] == 1
    forwarding = next(row for row in bom["claims"] if row["relation"] == "FORWARDS_TO")
    assert forwarding["confidence"] == "CONFIGURED"


def test_a_nic_attaches_to_a_segment_and_carries_an_address_as_an_observation():
    segment = h.hardware("NETWORK_SEGMENT", asset_tag="SEG-VLAN-40",
                         manufacturer="Cisco", model="VLAN-40", evidence_ids=[EVIDENCE],
                         vlan="VLAN-40", zone="PAYMENTS")
    server = server_part()
    nic = next(row for row in server["assets"] if row["kind"] == "NIC")
    bom = h.build(h.estate(h.merge(segment, server, {"assets": [], "claims": [
        h.claim(nic["name"], "ATTACHED_TO", segment["name"], basis="agent-inventory",
                evidence_ids=[EVIDENCE])]})))
    assert bom["counts"]["NETWORK_SEGMENT"] == 1  # a segment is hardware-adjacent
    assert nic["attributes"]["ip"] == "10.10.1.20"


# 7 — business system mapping --------------------------------------------------

def test_a_firmware_question_becomes_a_blast_radius_in_the_reviews_units():
    bom = h.build(payments())
    radius = h.radius(bom, query="HSM-001")
    assert radius["applications"] == ["Payments API"]
    assert "RSA-2048" in radius["crypto_assets"]
    # the business system sits behind a CMDB import, so the walk reports it as possible
    assert radius["possible"] and "Payments" in radius["possible"]


def test_the_graph_walks_from_a_business_system_down_to_the_hardware():
    bom = h.build(payments())
    server = next(row for row in bom["hardware_by_key"].values()
                  if row["kind"] == "PHYSICAL_SERVER")
    view = h.correlate(bom, server["name"])
    reached = {row["kind"] for rows in view["by_bom"].values() for row in rows}
    assert {"APPLICATION", "BUSINESS_SYSTEM"} <= reached


# 8 — firmware first-class -----------------------------------------------------

def test_firmware_is_a_release_with_a_lifecycle_not_a_string():
    release = firmware_row(status="EOL", eol_date="2026-09-30",
                           vulnerabilities=["CVE-2026-1111"])
    assert release["attributes"]["support_status"] == "EOL"
    assert release["attributes"]["eol_date"] == "2026-09-30"
    assert release["attributes"]["vulnerabilities"] == ["CVE-2026-1111"]


def test_an_unknown_firmware_status_is_refused_rather_than_stored():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.firmware("fw", version="1.0", status="PROBABLY-FINE", evidence_ids=[EVIDENCE])
    assert refused.value.code == "UNKNOWN_FIRMWARE_STATUS"


def test_a_release_that_has_ended_names_the_devices_that_run_it():
    bom = h.build(h.estate(hsm_part(firmware_release=firmware_row(status="EOL"))))
    lifecycle = bom["firmware_lifecycle"]
    assert len(lifecycle) == 1
    assert lifecycle[0]["actionable"] is True
    assert lifecycle[0]["devices"] == ["HSM-001"]
    assert lifecycle[0]["vulnerabilities"] == []


def test_a_vulnerability_is_its_own_asset_reachable_from_the_release():
    release = firmware_row(status="SUPPORTED")
    advisory = h.vulnerability("CVE-2026-1111", severity="HIGH",
                               affected_versions=["8.4.2"], evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge(hsm_part(firmware_release=release),
                                   {"assets": [advisory], "claims": [
                                       h.claim(release["name"], "HAS_VULNERABILITY",
                                               "CVE-2026-1111", basis="vendor-portal",
                                               evidence_ids=[EVIDENCE])]})))
    assert bom["counts"]["VULNERABILITY"] == 1
    advisory_edge = next(row for row in bom["claims"]
                         if row["relation"] == "HAS_VULNERABILITY")
    assert advisory_edge["confidence"] == "VENDOR_DECLARED"


# 9 — drift --------------------------------------------------------------------

def _drifted(**fields) -> dict:
    server = server_part(**fields)
    return h.build(h.estate(server))


def test_a_firmware_change_is_hardware_drift_with_the_crypto_behind_it():
    before = _drifted()
    after = h.build(h.estate(server_part(bios={"version": "2.6.0"})))
    feed = h.drift(before, after)
    assert feed["by_change"] == {"BIOS_CHANGED": 1}
    assert feed["hardware_drift"] is True
    assert feed["unmodelled_changes"] == []


def test_an_address_change_is_a_network_interface_change_not_a_new_device():
    before = _drifted()
    after = h.build(h.estate(server_part(nics=[{"model": "Broadcom 57414",
                                                "mac": "aa:bb:cc:00:11:22",
                                                "ip": "10.10.1.45",
                                                "vlan": "VLAN-40"}])))
    feed = h.drift(before, after)
    nic = next(row for row in before["assets"] if row["kind"] == "NIC")
    assert feed["by_change"] == {"NETWORK_INTERFACE_CHANGED": 1}
    assert feed["events"][0]["asset_id"] == nic["name"]
    assert "DEVICE_ADDED" not in feed["by_change"]


def test_an_hsm_firmware_change_is_named_as_an_hsm_change_and_drags_the_application():
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])

    def document(version: str) -> dict:
        return h.build(h.estate(h.merge(hsm_part(firmware_version=version),
                                        {"assets": [application], "claims": []})))

    before = document("8.4.2")
    after = document("8.5.0")
    feed = h.drift(before, after)
    assert feed["by_change"] == {"HSM_FIRMWARE_CHANGED": 2}
    assert feed["crypto_impact"]["applications"] == ["Payments API"]
    assert feed["crypto_impact"]["crypto_assets"]


def test_a_removed_component_is_device_removed_and_a_new_one_is_added():
    before = _drifted()
    server = server_part()
    after = h.build(h.estate({"assets": [row for row in server["assets"]
                                         if row["kind"] != "GPU"],
                              "claims": server["claims"]}))
    feed = h.drift(before, after)
    assert feed["by_change"] == {"DEVICE_REMOVED": 1}


def test_drift_refuses_a_document_that_is_not_an_hbom():
    with pytest.raises(ValueError):
        h.drift({"schema": "something-else"}, _drifted())


# 10 — identity ----------------------------------------------------------------

def test_an_ip_or_a_hostname_never_mints_a_device():
    first = h.identity(manufacturer="Dell", model="R760", serial_number="SN-1",
                       hostname="bank-srv-001", ip_addresses=["10.10.1.20"])
    second = h.identity(manufacturer="Dell", model="R760", serial_number="SN-1",
                        hostname="bank-srv-renamed", ip_addresses=["10.10.1.45"])
    assert first["asset_id"] == second["asset_id"]
    assert first["ignored_identifiers"]["ip_addresses"] == ["10.10.1.20"]


def test_a_device_known_only_by_network_identifiers_has_no_identity_at_all():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.identity(hostname="bank-srv-1", ip_addresses=["10.0.0.1"],
                   mac_addresses=["aa:bb:cc:00:11:22"])
    assert refused.value.code == "IDENTITY_WITHOUT_ANCHOR"


def test_a_manufacturer_and_model_alone_gives_a_provisional_identity():
    identity = h.identity(manufacturer="Dell", model="R760")
    assert identity["provisional"] is True and identity["durable"] is False
    assert "provisional" in identity["statement"]


def test_a_serial_number_makes_the_identity_durable():
    identity = h.identity(manufacturer="Dell", model="R760", serial_number="SN-1")
    assert identity["durable"] is True and identity["method"] == "serial"


# 11, 12 — virtual, cloud and container platforms ------------------------------

def test_physical_to_hypervisor_to_vm_to_os_to_application_is_one_chain():
    physical = h.hardware("PHYSICAL_SERVER", manufacturer="HPE", model="DL380",
                          serial_number="SN-P1", evidence_ids=[EVIDENCE])
    hypervisor = tb.asset("HYPERVISOR", "esxi-01", evidence_ids=[EVIDENCE])
    vm = tb.asset("VM", "payments-vm-01", evidence_ids=[EVIDENCE])
    os_asset = tb.asset("OS", "rhel-9.4", evidence_ids=[EVIDENCE])
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [physical, hypervisor, vm, os_asset,
                                               application], "claims": [
        h.claim(physical["name"], "RUNS_HYPERVISOR", "esxi-01", basis="agent-inventory",
                evidence_ids=[EVIDENCE]),
        h.claim("esxi-01", "RUNS_ON", physical["name"], basis="agent-inventory",
                evidence_ids=[EVIDENCE]),
        h.claim("payments-vm-01", "RUNS_ON", "esxi-01", basis="agent-inventory",
                evidence_ids=[EVIDENCE]),
        h.claim("payments-vm-01", "HOSTS_OS", "rhel-9.4", basis="agent-inventory",
                evidence_ids=[EVIDENCE]),
        h.claim("rhel-9.4", "RUNS_APPLICATION", "Payments API", basis="process-trace",
                evidence_ids=[EVIDENCE]),
    ]})))
    assert bom["refusals"] == []
    radius = h.radius(bom, query="esxi-01")
    assert radius["applications"] == ["Payments API"]
    assert "payments-vm-01" in radius["impacts"]["VM"]
    assert "rhel-9.4" in radius["impacts"]["OS"]


def test_a_cloud_instance_is_in_a_region_which_is_in_an_account():
    instance = tb.asset("CLOUD_INSTANCE", "i-0abc", evidence_ids=[EVIDENCE])
    region = tb.asset("CLOUD_REGION", "eu-west-1", evidence_ids=[EVIDENCE])
    account = tb.asset("CLOUD_ACCOUNT", "bank-prod", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [instance, region, account], "claims": [
        h.claim("i-0abc", "IN_REGION", "eu-west-1", basis="api-poll",
                evidence_ids=[EVIDENCE]),
        h.claim("eu-west-1", "IN_ACCOUNT", "bank-prod", basis="api-poll",
                evidence_ids=[EVIDENCE]),
    ]})))
    assert bom["refusals"] == []
    assert bom["counts"]["CLOUD_INSTANCE"] == 1


def test_a_pod_is_scheduled_on_a_kubernetes_node_and_never_on_a_cpu():
    pod = tb.asset("POD", "payments-api-7d9f", evidence_ids=[EVIDENCE])
    node = tb.asset("KUBERNETES_NODE", "k8s-node-3", evidence_ids=[EVIDENCE])
    cpu = h.hardware("CPU", asset_tag="ASSET-HW-000001-CPU", manufacturer="Intel",
                     model="Xeon 6430", evidence_ids=[EVIDENCE])
    document = h.estate(h.merge({"assets": [pod, node, cpu], "claims": [
        h.claim("payments-api-7d9f", "SCHEDULED_ON", "k8s-node-3", basis="api-poll",
                evidence_ids=[EVIDENCE]),
        h.claim("payments-api-7d9f", "SCHEDULED_ON", cpu["name"], basis="api-poll",
                evidence_ids=[EVIDENCE]),
    ]}))
    bom = h.build(document)
    assert [row["code"] for row in bom["refusals"]] == ["TYPE_MISMATCH"]


# 13 — the evidence model ------------------------------------------------------

def test_evidence_needs_a_collector_a_time_and_a_hash():
    payload = {"evidence_id": "E1", "collector": "agent", "observed_at": NOW,
               "hash": "sha256:ab"}
    for field, code in (("collector", "EVIDENCE_WITHOUT_COLLECTOR"),
                        ("observed_at", "EVIDENCE_WITHOUT_TIME"),
                        ("hash", "EVIDENCE_WITHOUT_HASH")):
        with pytest.raises(tb.ClaimRefused) as refused:
            h.evidence(**{**payload, field: None})
        assert refused.value.code == code


def test_the_register_keeps_the_full_record_for_every_device():
    record = ev()
    device = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                        evidence=[record])
    bom = h.build(h.estate(h.merge({"assets": [device], "claims": []})))
    stored = bom["evidence_register"][EVIDENCE]
    assert stored["collector_version"] == "1.4.2"
    assert stored["hash"] == "sha256:3b1f"
    assert stored["evidence_type"] == "INVENTORY"


def test_a_hardware_asset_without_evidence_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.hardware("HSM", manufacturer="X", model="Y")
    assert refused.value.code == "HARDWARE_WITHOUT_EVIDENCE"


# 14 — coverage ----------------------------------------------------------------

def test_coverage_accounts_for_every_expected_device():
    block = h.coverage(200, 120, unavailable=50, permission_denied=20, unknown=10)
    assert block["verdict"] == "PARTIAL" and block["coverage"] == 0.6
    assert "permission denied 20" in block["statement"]


def test_coverage_that_does_not_add_up_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.coverage(200, 120, unavailable=50, permission_denied=10, unknown=10)
    assert refused.value.code == "COVERAGE_DOES_NOT_RECONCILE"


def test_an_estate_that_meets_its_denominator_is_complete():
    assert h.coverage(120, 120)["verdict"] == "COMPLETE"


# 15 — cross-BOM correlation ---------------------------------------------------

def test_one_hardware_asset_walks_into_five_views():
    bom = h.build(payments())
    linked = h.correlate(bom, "HSM-001")
    assert linked["seed"] == "HSM-001"
    assert {"HBOM", "CBOM", "VBOM"} <= set(linked["by_bom"])
    assert linked["views"] >= 3


def test_a_link_is_a_reference_and_not_a_copy():
    bom = h.build(payments())
    link = h.bom_link(bom)
    assert link["link"].startswith("bom-link:hbom:")
    assert "rows" not in link and "assets" not in link


# 16 — not a source of truth ---------------------------------------------------

def test_an_hbom_cannot_be_built_from_an_hbom():
    bom = h.build(payments())
    with pytest.raises(ValueError, match="not a source"):
        h.from_document(bom)
    with pytest.raises(ValueError, match="not a source"):
        h.build(bom)


def test_the_hbom_is_the_techbom_restricted_to_hardware():
    document = payments()
    techbom_doc = tb.build(document)
    hbom_doc = h.build(document)
    hardware_keys = {row["key"] for row in hbom_doc["assets"]}
    assert hardware_keys <= set(techbom_doc["by_key"])
    assert {row["key"] for row in hbom_doc["assets"]} \
        <= {row["key"] for row in techbom_doc["assets"]}
    assert hbom_doc["techbom"]["assets"] == len(techbom_doc["assets"])


def test_the_same_estate_produces_the_same_hardware_ids_twice():
    first = h.build(payments())
    second = h.build(payments())
    assert [row["id"] for row in first["assets"]] == [row["id"] for row in second["assets"]]
    assert first["statement"] == second["statement"]


# the adapter from stored hardware rows ---------------------------------------

def _row(**fields) -> dict:
    body = {"id": 1, "asset_id": "HSM-001", "manufacturer": "SyntheticHSM",
            "model": "PaymentHSM-9000", "device_type": "hsm", "serial_reference": "SN-1",
            "hardware_revision": "B2", "last_seen": "2026-11-03T08:30:00+00:00",
            "first_seen": "2026-01-04T00:00:00+00:00", "current_fingerprint": "ab" * 32,
            "firmware": {"version": "8.4.2", "status": "EOL",
                         "eol_date": "2026-09-30"},
            "crypto_capabilities": {"RSA-2048": {"key_sizes": [2048],
                                                 "operations": ["SIGN"]}}}
    body.update(fields)
    return body


def test_stored_rows_become_devices_with_their_own_fingerprint_as_evidence():
    body = h.stored_hardware([_row()])
    bom = h.build(h.estate({"assets": body["assets"], "claims": body["claims"]}))
    device = next(row for row in bom["assets"] if row["kind"] == "HSM")
    record = bom["evidence_register"][device["evidence_ids"][0]]
    assert record["hash"] == "ab" * 32
    assert record["collector"] == "hardware-agent"
    assert bom["claims"][0]["confidence"] == "CONFIGURED"


def test_a_stored_row_never_claims_observed():
    body = h.stored_hardware([_row()])
    bom = h.build(h.estate({"assets": body["assets"], "claims": body["claims"]}))
    read = {row["confidence"] for row in bom["claims"]
            if row["relation"] not in {"HAS_MODEL", "SUPPLIED_BY"}}
    assert read == {"CONFIGURED"}
    # the vendor chain is the row's claim about the product, not an observation of it
    declared = {row["confidence"] for row in bom["claims"]
                if row["relation"] in {"HAS_MODEL", "SUPPLIED_BY"}}
    assert declared == {"VENDOR_DECLARED"}
    assert "CONFIGURED at best" in body["statement"]


def test_a_device_type_the_model_cannot_place_is_skipped_with_a_reason():
    body = h.stored_hardware([_row(device_type="toaster")])
    assert body["assets"] == []
    assert "device_type" in body["skipped"][0]["reason"]


def test_a_row_with_no_observation_time_cannot_cite_evidence():
    body = h.stored_hardware([_row(last_seen=None, first_seen=None)])
    assert body["assets"] == []
    assert "observation time" in body["skipped"][0]["reason"]


def test_a_row_without_a_fingerprint_hashes_its_own_content_and_says_medium():
    body = h.stored_hardware([_row(current_fingerprint=None)])
    record = body["assets"][0]["attributes"]["evidence"][0]
    assert record["hash"].startswith("sha256:") and record["confidence"] == "MEDIUM"


def test_a_stored_firmware_string_is_a_release_and_a_dict_is_a_lifecycle():
    plain = h.stored_hardware([_row(firmware="8.4.2")])
    rich = h.stored_hardware([_row()])
    assert any(row["kind"] == "FIRMWARE" for row in plain["assets"])
    release = next(row for row in rich["assets"] if row["kind"] == "FIRMWARE")
    assert release["attributes"]["support_status"] == "EOL"


def test_stored_capabilities_are_supports_claims_not_uses():
    body = h.stored_hardware([_row()])
    relations = {claim["relation"] for claim in body["claims"]}
    assert relations == {"RUNS_FIRMWARE", "SUPPORTS", "HAS_MODEL", "SUPPLIED_BY"}


# ---- what the second read of the review added -------------------------------

def test_a_cpu_is_a_topology_that_has_to_reconcile():
    topology = h.cpu_topology(sockets=2, cores_per_socket=16, threads_per_core=2,
                              numa_nodes=2, frequency_mhz=2600)
    assert topology["cores"] == 32 and topology["threads"] == 64
    assert "2 socket(s) x 16 core(s)" in topology["topology"]
    with pytest.raises(tb.ClaimRefused) as refused:
        h.cpu_topology(sockets=2, cores_per_socket=16, threads_per_core=2, cores=48)
    assert refused.value.code == "TOPOLOGY_DOES_NOT_RECONCILE"


def test_a_certification_names_a_standard_and_says_whether_it_is_backed():
    backed = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                        certifications=[{"standard": "FIPS 140-3", "level": "Level 3",
                                         "expires": "2027-06-30",
                                         "evidence_id": EVIDENCE}])
    unbacked = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                          certifications=["Common Criteria EAL4+"])
    assert backed["attributes"]["certifications"][0]["backed"] is True
    assert unbacked["attributes"]["certifications"][0]["backed"] is False
    with pytest.raises(tb.ClaimRefused) as refused:
        h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                   certifications=[{"level": "Level 3"}])
    assert refused.value.code == "CERTIFICATION_WITHOUT_STANDARD"


def test_a_sku_is_kept_beside_the_part_number():
    row = h.hardware("PHYSICAL_SERVER", manufacturer="Dell", model="R760",
                     sku="PER760-32C", part_number="0R760A", evidence_ids=[EVIDENCE])
    assert row["attributes"]["sku"] == "PER760-32C"
    assert row["attributes"]["part_number"] == "0R760A"


def test_a_host_runs_what_sits_on_it_as_well_as_the_other_way_round():
    host = h.hardware("PHYSICAL_SERVER", manufacturer="Dell", model="R760",
                      serial_number="SN-1", evidence_ids=[EVIDENCE])
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [host, application], "claims": [
        h.claim(host["name"], "RUNS", "Payments API", basis="process-trace",
                evidence_ids=[EVIDENCE]),
        h.claim("Payments API", "RUNS_ON", host["name"], basis="config-parse",
                evidence_ids=[EVIDENCE]),
    ]})))
    assert bom["refusals"] == []
    assert {(row["relation"], row["confidence"]) for row in bom["claims"]} == {
        ("RUNS", "OBSERVED"), ("RUNS_ON", "CONFIGURED")}


def test_a_host_cannot_run_an_algorithm():
    host = h.hardware("PHYSICAL_SERVER", manufacturer="Dell", model="R760",
                      serial_number="SN-1", evidence_ids=[EVIDENCE])
    algorithm = tb.asset("ALGORITHM", "RSA-2048", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [host, algorithm], "claims": [
        h.claim(host["name"], "RUNS", "RSA-2048", basis="process-trace",
                evidence_ids=[EVIDENCE])]})))
    assert bom["refusals"][0]["code"] == "TYPE_MISMATCH"


def test_capability_and_network_observation_are_classes_of_their_own():
    assert tb.BASES["capability-list"] == tb.CAPABILITY
    assert tb.CAPABILITY in tb.CONFIDENCE and tb.CAPABILITY not in tb.PROVEN
    assert tb.BASES["passive-capture"] == tb.NETWORK_OBSERVED
    assert tb.NETWORK_OBSERVED in tb.PROVEN
    claim = tb.claim("HSM-001", "SUPPORTS", "cap RSA", basis="capability-list",
                     evidence_ids=[EVIDENCE])
    assert claim["confidence"] == tb.CAPABILITY


def test_a_network_appliance_carries_its_facts_and_its_two_references():
    balancer = h.network_device(
        "LOAD_BALANCER", name="payments-lb", manufacturer="F5", model="BIG-IP i5800",
        firmware_version="17.1.1", ip="10.10.0.20", mac="aa:bb:cc:00:20:01",
        interface="1.1", vlan="VLAN-10", zone="EDGE", subnet="10.10.0.0/24",
        routing="static-default", ha_role="ACTIVE",
        tls={"min_version": "TLS1.2", "pqc": "hybrid-x25519mlkem768"},
        certificate="cert:payments-edge", hsm="HSM-001", evidence_ids=[EVIDENCE])
    attributes = balancer["assets"][0]["attributes"]
    for name in ("ip", "mac", "interface", "vlan", "zone", "subnet", "routing",
                 "ha_role", "firmware_version", "tls_capability",
                 "certificate_reference", "hsm_reference"):
        assert attributes.get(name), name
    relations = {claim["relation"] for claim in balancer["claims"]}
    assert relations == {"PRESENTS", "USES_HSM"}


def test_a_builder_refuses_a_kind_it_does_not_model():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.network_device("ROUTER", manufacturer="Cisco", model="ASR",
                         evidence_ids=[EVIDENCE])
    assert refused.value.code == "NOT_A_NETWORK_DEVICE"


def test_a_product_past_end_of_life_reaches_the_business_behind_it():
    product = h.product("SyntheticHSM PaymentHSM-9000", vendor="SyntheticHSM",
                        model="PaymentHSM-9000", status="RETIRED",
                        eol_date="2026-09-30", replacement="PaymentHSM-9100",
                        evidence_ids=[EVIDENCE])
    device = h.hsm("HSM-001", vendor="SyntheticHSM", product="PaymentHSM-9000",
                   model="PaymentHSM-9000", firmware_version="8.4.2",
                   applications=["Payments API"], systems=["Payments"],
                   evidence_ids=[EVIDENCE], product_asset=product)
    application = tb.asset("APPLICATION", "Payments API", evidence_ids=[EVIDENCE])
    system = tb.asset("BUSINESS_SYSTEM", "Payments", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge(device, {"assets": [application, system],
                                            "claims": []})))
    lifecycle = h.product_lifecycle(bom)
    ended = lifecycle["products"][0]
    assert ended["status"] == "RETIRED" and ended["actionable"] is True
    assert ended["devices"] == ["HSM-001"]
    assert ended["systems"] == ["Payments"]
    assert ended["replacement"] == "PaymentHSM-9100"


def test_a_product_status_this_model_does_not_know_is_refused():
    with pytest.raises(tb.ClaimRefused) as refused:
        h.product("p", vendor="v", status="PROBABLY-FINE", evidence_ids=[EVIDENCE])
    assert refused.value.code == "UNKNOWN_PRODUCT_STATUS"


def test_the_review_sentence_is_a_measurement_over_the_graph():
    bom = h.build(payments())
    summary = h.impact_summary(bom, query="HSM-001")
    assert summary["hsm"] >= 1 and summary["applications"] >= 1
    assert "affected" in summary["statement"]
    assert summary["crypto_assets"] >= 1


def test_a_swapped_unit_in_the_same_bay_is_one_device_replaced_event():
    def device(identifier: str, serial: str) -> dict:
        return h.hardware("HSM", asset_id=identifier, manufacturer="SyntheticHSM",
                          model="PaymentHSM-9000", serial_number=serial,
                          rack="R12", slot="U8", evidence_ids=[EVIDENCE])

    before = h.build(h.estate(h.merge(device("HSM-001", "SN-1"))))
    after = h.build(h.estate(h.merge(device("HSM-009", "SN-9"))))
    feed = h.drift(before, after)
    replaced = [event for event in feed["events"]
                if event["change"] == "DEVICE_REPLACED"]
    assert len(replaced) == 1
    assert replaced[0]["previous_asset_id"] == "HSM-001"
    assert replaced[0]["asset_id"] == "HSM-009"
    assert "DEVICE_ADDED" not in feed["by_change"]
    assert "DEVICE_REMOVED" not in feed["by_change"]


def test_a_device_in_a_free_bay_is_still_an_addition():
    before = h.build(h.estate(h.merge(h.hardware(
        "HSM", asset_id="HSM-001", manufacturer="X", model="Y", serial_number="SN-1",
        rack="R12", slot="U8", evidence_ids=[EVIDENCE]))))
    after = h.build(h.estate(h.merge(h.hardware(
        "HSM", asset_id="HSM-002", manufacturer="X", model="Y", serial_number="SN-2",
        rack="R13", slot="U1", evidence_ids=[EVIDENCE]))))
    assert h.drift(before, after)["by_change"] == {"DEVICE_ADDED": 1, "DEVICE_REMOVED": 1}


def test_evidence_becomes_a_node_and_a_device_an_edge_to_it():
    record = ev()
    device = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                        evidence=[record])
    bom = h.build(h.estate(h.merge({"assets": [device], "claims": []})))
    node = next(row for row in bom["assets"] if row["kind"] == "EVIDENCE")
    assert node["name"] == EVIDENCE and node["attributes"]["hash"] == "sha256:3b1f"
    edge = next(row for row in bom["claims"] if row["relation"] == "EVIDENCED_BY")
    assert edge["to"] == EVIDENCE and edge["confidence"] == "CONFIGURED"


def test_an_evidence_edge_cannot_be_an_inference():
    record = ev()
    device = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE],
                        evidence=[record])
    node = tb.asset("EVIDENCE", EVIDENCE, evidence_ids=[EVIDENCE], hash="sha256:3b1f")
    bom = h.build(h.estate(h.merge({"assets": [device, node], "claims": [
        h.claim(device["name"], "EVIDENCED_BY", EVIDENCE, basis="name-match",
                rule="a similar name", evidence_ids=[EVIDENCE])]})))
    assert "CLAIM_WEAKER_THAN_RELATION_REQUIRES" in [row["code"]
                                                     for row in bom["refusals"]]


def test_an_hsm_certificate_is_a_node_with_an_edge_from_the_device():
    device = h.hsm("HSM-001", vendor="SyntheticHSM", product="P-9000", model="P-9000",
                   firmware_version="8.4.2", certificates=["cert:payments-root"],
                   evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge(device)))
    assert any(row["kind"] == "CERTIFICATE" and row["name"] == "cert:payments-root"
               for row in bom["assets"])
    edge = next(row for row in bom["claims"]
                if row["relation"] == "HOLDS_CERTIFICATE")
    assert edge["from"] == "HSM-001" and edge["to"] == "cert:payments-root"


def test_a_key_reference_cannot_be_held_as_a_certificate():
    device = h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVIDENCE])
    reference = tb.asset("KEY_REFERENCE", "KREF-0007", evidence_ids=[EVIDENCE])
    bom = h.build(h.estate(h.merge({"assets": [device, reference], "claims": [
        h.claim(device["name"], "HOLDS_CERTIFICATE", "KREF-0007", basis="api-poll",
                evidence_ids=[EVIDENCE])]})))
    assert bom["refusals"][0]["code"] == "TYPE_MISMATCH"

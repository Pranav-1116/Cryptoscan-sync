"""OT coverage & segmentation: EtherNet/IP, IEC-104, PROFINET, MQTT, zones/conduits,
multicast MAC enrichment, observation dedup, provenance, CVE table growth."""

from __future__ import annotations

from ot_scanner.core.scanner import OtPassiveScanner, _version_lt, lookup_cves
from ot_scanner.protocols import enip, iec104, iec61850, mqtt, profinet
from ot_scanner.reports.metrics import render_prometheus
from ot_scanner.reports.posture import build_ot_posture
from ot_scanner.reports.zones import cross_zone_flows, derive_zones


# --------------------------------------------------------------------------- #
# new protocol analyzers
# --------------------------------------------------------------------------- #

def test_ethernetip_plain_and_tls():
    plain = enip.analyze({"port": "44818"})
    assert plain["compliance_issue"] == "OT_UNENCRYPTED_ETHERNETIP" and plain["has_crypto"] is False
    secure = enip.analyze({"tls": "true"})
    assert secure["security_level"] == "ENCRYPT" and "CIP Security" in secure["crypto"]["encryption"]


def test_iec104_plain_and_tls():
    plain = iec104.analyze({"port": "2404"})
    assert plain["protocol"] == "IEC-104"
    assert plain["compliance_issue"] == "OT_UNENCRYPTED_IEC104"
    assert "62351" in plain["note"]
    secure = iec104.analyze({"tls": "1"})
    assert secure["has_crypto"] is True and secure["compliance_issue"] is None


def test_profinet_has_no_security_by_design():
    finding = profinet.analyze({})
    assert finding["compliance_issue"] == "OT_UNENCRYPTED_PROFINET"
    assert finding["crypto"]["encryption"] == "NONE"


def test_mqtt_port_8883_implies_tls():
    assert mqtt.analyze({"port": "1883"})["compliance_issue"] == "OT_UNENCRYPTED_MQTT"
    over_tls = mqtt.analyze({"port": "8883"})
    assert over_tls["has_crypto"] is True and over_tls["compliance_issue"] is None
    explicit = mqtt.analyze({"port": "1883", "tls": "true"})
    assert explicit["security_level"] == "ENCRYPT"


def test_new_protocols_detected_from_log_lines(tmp_path):
    log = tmp_path / "plant.otlog"
    log.write_text(
        "ts=x src=10.1.1.10 dst=10.1.1.20 port=44818\n"          # EtherNet/IP by port
        "ts=x src=10.2.1.10 port=2404\n"                          # IEC-104 by port
        "ts=x src=10.3.1.10 product=Siemens-GSD-Profinet-IO\n"    # PROFINET by token
        "ts=x src=10.4.1.10 port=1883 topic=plant/line1/pv\n"     # MQTT by port
        "ts=x src=10.5.1.10 dst=10.5.1.20 protocol=iec-104\n"     # IEC-104 by token
    )
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    protocols = {row["protocol"] for row in result["findings"]}
    assert {"EtherNet/IP", "IEC-104", "PROFINET", "MQTT"} <= protocols


def test_device_types_for_new_protocols(tmp_path):
    log = tmp_path / "types.otlog"
    log.write_text(
        "ts=x src=10.1.1.10 port=44818\n"
        "ts=x src=10.2.1.10 port=2404\n"
        "ts=x src=10.4.1.10 port=1883\n"
    )
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    types = {row["ip_address"]: row["device_type"] for row in result["devices"]}
    assert types["10.1.1.10"] == "PLC"
    assert types["10.2.1.10"] == "RTU"
    assert types["10.4.1.10"] == "GATEWAY"


# --------------------------------------------------------------------------- #
# CVE table + version matching
# --------------------------------------------------------------------------- #

def test_siprotec_cve_matched_and_bounded():
    hit = lookup_cves(
        {
            "vendor": "Siemens",
            "model": "SIPROTEC 4",
            "firmware_version": "4.24",
        }
    )
    assert [row["cve"] for row in hit] == ["CVE-2015-5374"]
    fixed = lookup_cves({"vendor": "Siemens", "model": "SIPROTEC 4", "firmware_version": "4.25"})
    assert fixed == []


def test_version_compare_pads_parts():
    assert _version_lt("2.8", "2.9.0") is True
    assert _version_lt("2.9", "2.9.0") is False  # "2.9" means 2.9.0, not less than it
    assert _version_lt("V2.8.2", "2.9") is True
    assert _version_lt("4.24.17", "4.25") is True


def test_s7_1500_still_matches_only_below_290():
    hit = lookup_cves({"vendor": "Siemens", "model": "S7-1500", "firmware_version": "2.8.2"})
    assert [row["cve"] for row in hit] == ["CVE-2020-15782"]
    assert lookup_cves({"vendor": "Siemens", "model": "S7-1500", "firmware_version": "2.9"}) == []


# --------------------------------------------------------------------------- #
# zones & conduits (IEC 62443 approximation)
# --------------------------------------------------------------------------- #

def _flow(src, dst, *, encrypted=False, protocol="Modbus TCP", criticality="AUXILIARY"):
    return {
        "protocol": protocol,
        "security_level": "ENCRYPT" if encrypted else "NONE",
        "has_crypto": encrypted,
        "compliance_issue": None if encrypted else "OT_UNENCRYPTED_MODBUS",
        "device": {"ip_address": src, "criticality": criticality},
        "source": {"type": "OT_NETWORK_TRAFFIC", "src_ip": src, "dst_ip": dst},
    }


def test_cross_zone_flow_detection():
    findings = [_flow("10.1.0.5", "10.1.0.9"), _flow("10.1.0.5", "10.2.0.9"), _flow("10.1.0.5", "10.2.0.9", encrypted=True)]
    crossing = cross_zone_flows(findings)
    assert len(crossing) == 1
    assert crossing[0]["src_zone"] == "10.1.0.0/24" and crossing[0]["dst_zone"] == "10.2.0.0/24"


def test_broadcast_and_multicast_dst_not_a_conduit():
    assert cross_zone_flows([_flow("10.1.0.5", "10.1.255.255")]) == []
    assert cross_zone_flows([_flow("10.1.0.5", "224.0.1.4")]) == []  # GOOSE-style multicast


def test_derive_zones_structure():
    zones = derive_zones([_flow("10.1.0.5", "10.2.0.9", protocol="Modbus TCP"), _flow("10.1.0.5", "10.1.0.8")])
    assert zones["zone_count"] == 2
    by_zone = {row["zone"]: row for row in zones["zones"]}
    assert by_zone["10.1.0.0/24"]["devices"] == ["10.1.0.5", "10.1.0.8"]
    # each unencrypted flow counted once against its source zone
    assert by_zone["10.1.0.0/24"]["unencrypted_flows"] == 2
    assert by_zone["10.2.0.0/24"]["unencrypted_flows"] == 0
    assert zones["cross_zone_unencrypted"] == 1
    assert "approximation" in zones["semantics"]


def test_posture_flags_cross_zone_as_warn():
    report = build_ot_posture(findings=[_flow("10.1.0.5", "10.2.0.9")], devices=[{"ip_address": "10.1.0.5"}])
    assert report["posture"] == "WARN"  # WARN tier, not FAIL
    assert "OT_CROSS_ZONE_UNENCRYPTED" in report["policy_issues"]
    assert report["cross_zone_unencrypted_flows"] == 1
    clean = build_ot_posture(
        findings=[_flow("10.1.0.5", "10.2.0.9", encrypted=True)], devices=[{"ip_address": "10.1.0.5"}]
    )
    assert "OT_CROSS_ZONE_UNENCRYPTED" not in clean["policy_issues"]


def test_scan_result_carries_zones(tmp_path):
    log = tmp_path / "cross.otlog"
    log.write_text(
        "ts=x src=10.1.0.5 dst=10.2.0.9 port=502\n"
        "ts=x src=10.2.0.9 dst=10.1.0.5 port=502\n"
    )
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert result["zones"]["zone_count"] == 2
    assert result["zones"]["cross_zone_unencrypted"] == 2
    assert "OT_CROSS_ZONE_UNENCRYPTED" in result["risk_report"]["policy_issues"]


# --------------------------------------------------------------------------- #
# multicast MAC enrichment + observation dedup + provenance
# --------------------------------------------------------------------------- #

def test_goose_multicast_mac_enriched():
    finding = iec61850.analyze({"protocol": "goose", "dst_mac": "01:0C:CD:01:00:07"})
    assert finding["multicast"] is True
    assert finding["multicast_mac"] == "01:0C:CD:01:00:07"
    plain = iec61850.analyze({"protocol": "goose"})
    assert "multicast" not in plain


def test_observation_summary_dedupes(tmp_path):
    log = tmp_path / "dupes.otlog"
    log.write_text(
        "ts=x src=10.0.0.7 dst=10.0.0.1 port=502\n"
        "ts=x src=10.0.0.7 dst=10.0.0.1 port=502\n"
        "ts=x src=10.0.0.7 dst=10.0.0.1 port=502\n"
    )
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert len(result["findings"]) == 3
    assert len(result["observation_summary"]) == 1
    entry = result["observation_summary"][0]
    assert entry["observations"] == 3 and entry["unencrypted"] is True
    assert entry["first_source"]["file"].endswith("dupes.otlog")
    assert entry["first_source"]["line"] == 1 and entry["last_source"]["line"] == 3


def test_finding_provenance_carries_line_number(tmp_path):
    log = tmp_path / "prov.otlog"
    log.write_text("# comment line\n\nts=x src=10.0.0.9 port=502\n")
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert result["findings"][0]["source"]["line"] == 3
    assert result["findings"][0]["source"]["file_path"].endswith("prov.otlog")


# --------------------------------------------------------------------------- #
# metrics extension
# --------------------------------------------------------------------------- #

def test_metrics_zone_families():
    payload = {
        "zones": {"zone_count": 3, "cross_zone_unencrypted": 2},
        "observation_summary": [{"device": "a"}, {"device": "b"}],
        "risk_report": {"posture": "WARN", "device_count": 2, "devices_with_cves": []},
    }
    text = render_prometheus(payload)
    assert "cryptoscan_ot_zones 3" in text
    assert "cryptoscan_ot_cross_zone_unencrypted_flows 2" in text
    assert "cryptoscan_ot_distinct_observations 2" in text
    assert "cryptoscan_ot_packets_sent 0" in text


def test_metrics_without_zones_unchanged():
    text = render_prometheus({"risk_report": {"posture": "PASS", "device_count": 1, "devices_with_cves": []}})
    assert "cryptoscan_ot_zones" not in text
    assert "cryptoscan_ot_distinct_observations" not in text

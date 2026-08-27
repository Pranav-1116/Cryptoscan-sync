"""Passive OT/ICS crypto scanner. Reads logs / JSON captures. Never sends packets."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ot_scanner.core.safety import OtSafetyError, forbid, send_packet
from ot_scanner.protocols import dnp3, enip, iec104, iec61850, modbus, mqtt, opcua, profinet, s7comm

OUI = {
    "00:1B:1B": "Siemens",
    "00:00:BC": "Allen-Bradley",
    "00:0E:8C": "Schneider Electric",
    "00:01:4B": "ABB",
}

CVE_TABLE = (
    {
        "vendor": "Siemens",
        "product": "S7-1500",
        "max_exclusive": "2.9.0",
        "cve": "CVE-2020-15782",
        "cvss": 9.1,
        "summary": "Hardcoded encryption key in firmware",
    },
    {
        # CISA ICSA-15-202-01: EN100 module V4.24 or prior; fixed in V4.25
        "vendor": "Siemens",
        "product": "SIPROTEC",
        "max_exclusive": "4.25",
        "cve": "CVE-2015-5374",
        "cvss": 7.8,
        "summary": "Remote DoS via crafted UDP/50000 packets (EN100 Ethernet module)",
    },
)

KV = re.compile(r"([A-Za-z0-9_]+)=((?:(?!\s+[A-Za-z0-9_]+=).)+)")
MAX_RECORDS = 1000
OT_SUFFIXES = {".log", ".otlog", ".pcap.txt", ".jsonl", ".ndjson"}


class OtPassiveScanner:
    mode = "PASSIVE_OBSERVATION"

    def __init__(self) -> None:
        self.stopped = False
        self.packets_emitted = 0

    def emergency_stop(self) -> None:
        self.stopped = True

    def send_packet(self, *args, **kwargs) -> None:  # noqa: ANN002
        send_packet(*args, **kwargs)

    def scan_filesystem(self, root: str | Path, *, scan_id: str | None = None) -> dict[str, Any]:
        if self.stopped:
            return {"scan_id": scan_id, "stopped": True, "devices": [], "findings": [], "packets_sent": 0}
        root_path = Path(root)
        records: list[dict[str, Any]] = []
        if root_path.is_file():
            records.extend(self._parse_file(root_path))
        elif root_path.exists():
            for path in sorted(root_path.rglob("*")):
                if self.stopped:
                    break
                if not path.is_file():
                    continue
                name = path.name.lower()
                if path.suffix.lower() not in OT_SUFFIXES and "ot" not in path.parts and "ot-lab" not in path.parts:
                    if not any(token in name for token in ("opcua", "modbus", "dnp3", "iec61850", "iec-61850")):
                        continue
                records.extend(self._parse_file(path))
                if len(records) >= MAX_RECORDS:
                    records = records[:MAX_RECORDS]
                    break
        return self._summarize(records, scan_id=scan_id)

    def scan_records(self, records: list[dict[str, Any]], *, scan_id: str | None = None) -> dict[str, Any]:
        return self._summarize(records[:MAX_RECORDS], scan_id=scan_id)

    def _parse_file(self, path: Path) -> list[dict[str, Any]]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            return self._parse_json(stripped, path)
        out = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(out) >= MAX_RECORDS:
                break
            rec = self._parse_line(line)
            if rec:
                rec["source_file"] = str(path)
                rec["source_line"] = lineno
                out.append(rec)
        return out

    def _parse_json(self, text: str, path: Path) -> list[dict[str, Any]]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            rows = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    item["source_file"] = str(path)
                    rows.append(item)
            return rows
        if isinstance(data, list):
            out = []
            for item in data:
                if isinstance(item, dict):
                    item["source_file"] = str(path)
                    out.append(item)
            return out
        if isinstance(data, dict):
            data["source_file"] = str(path)
            return [data]
        return []

    def _parse_line(self, line: str) -> dict[str, Any] | None:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            return None
        fields = {match.group(1).lower(): match.group(2) for match in KV.finditer(raw)}
        if not fields:
            return None
        proto = (fields.get("proto") or fields.get("protocol") or "").lower()
        port = fields.get("port") or ""
        port_proto = {"44818": "ethernetip", "2222": "ethernetip", "2404": "iec104", "1883": "mqtt", "8883": "mqtt"}.get(port)
        if not proto and port_proto:
            proto = port_proto
        if not proto:
            if port == "4840" or "opcua" in raw.lower() or "opc-ua" in raw.lower():
                proto = "opcua"
            elif port == "502" or "modbus" in raw.lower():
                proto = "modbus"
            elif port == "20000" or "dnp3" in raw.lower():
                proto = "dnp3"
            elif "goose" in raw.lower():
                proto = "goose"
            elif "sampledvalues" in raw.lower().replace("-", "").replace("_", ""):
                proto = "sv"
            elif "s7" in raw.lower():
                proto = "s7comm"
            elif "ethernet-ip" in raw.lower() or "ethernetip" in raw.lower() or "enip" in raw.lower():
                proto = "ethernetip"
            elif "iec-104" in raw.lower() or "iec104" in raw.lower() or "60870" in raw.lower():
                proto = "iec104"
            elif "profinet" in raw.lower():
                proto = "profinet"
            elif "mqtt" in raw.lower():
                proto = "mqtt"
            elif port == "102" or "61850" in raw.lower():
                proto = "iec61850"
        if not proto:
            return None
        fields["protocol"] = proto
        fields["src_ip"] = fields.get("src") or fields.get("src_ip")
        fields["dst_ip"] = fields.get("dst") or fields.get("dst_ip")
        fields["mac_address"] = fields.get("mac") or fields.get("mac_address")
        return fields

    def _summarize(self, records: list[dict[str, Any]], *, scan_id: str | None) -> dict[str, Any]:
        devices: dict[str, dict[str, Any]] = {}
        findings: list[dict[str, Any]] = []
        for record in records:
            proto = str(record.get("protocol") or "").lower()
            if "opc" in proto:
                analysis = opcua.analyze(record)
            elif "modbus" in proto:
                analysis = modbus.analyze(record)
            elif "dnp" in proto:
                analysis = dnp3.analyze(record)
            elif "goose" in proto or proto == "sv" or "sampled" in proto:
                analysis = iec61850.analyze(record)
            elif "s7" in proto:
                analysis = s7comm.analyze(record)
            elif "ethernet" in proto or proto in {"enip", "cip"}:
                analysis = enip.analyze(record)
            elif "104" in proto or "60870" in proto:
                analysis = iec104.analyze(record)
            elif "profinet" in proto or proto == "pnio":
                analysis = profinet.analyze(record)
            elif "mqtt" in proto:
                analysis = mqtt.analyze(record)
            elif "61850" in proto or "iec" in proto:
                analysis = iec61850.analyze(record)
            else:
                continue
            ip = record.get("src_ip") or record.get("src") or record.get("ip_address") or "unknown"
            device = devices.setdefault(
                str(ip),
                {
                    "ip_address": ip,
                    "mac_address": record.get("mac_address") or record.get("mac"),
                    "vendor": None,
                    "device_type": record.get("device_type") or self._guess_type(analysis["protocol"]),
                    "model": record.get("model") or record.get("product"),
                    "firmware_version": record.get("firmware_version") or record.get("version"),
                    "protocols_observed": [],
                    "location": record.get("location"),
                    "criticality": record.get("criticality") or "SAFETY_CRITICAL",
                },
            )
            device["vendor"] = device.get("vendor") or self._vendor(record)
            proto_name = analysis["protocol"]
            if proto_name not in device["protocols_observed"]:
                device["protocols_observed"].append(proto_name)
            if record.get("product") and not device.get("model"):
                device["model"] = record.get("product")
            cves = lookup_cves(device)
            finding = {
                **analysis,
                "source": {
                    "type": "OT_NETWORK_TRAFFIC",
                    "protocol": analysis["protocol"],
                    "src_ip": ip,
                    "dst_ip": record.get("dst_ip") or record.get("dst"),
                    "file_path": record.get("source_file"),
                    "line": record.get("source_line"),
                    "language": "OT",
                },
                "device": device,
                "vulnerabilities": cves,
                "metadata": {
                    "confidence": "MEDIUM",
                    "detection_method": "PASSIVE_PACKET_INSPECTION",
                    "scanner_mode": self.mode,
                },
            }
            findings.append(finding)
        unencrypted = [row for row in findings if not row.get("has_crypto")]
        from ot_scanner.reports.posture import build_ot_posture, build_ot_telemetry
        from ot_scanner.reports.zones import derive_zones

        device_rows = list(devices.values())
        summary: dict[tuple[str, str, str], dict[str, Any]] = {}
        for finding in findings:
            src = finding.get("source") or {}
            key = (
                str((finding.get("device") or {}).get("ip_address")),
                str(finding.get("protocol")),
                str(finding.get("compliance_issue")),
            )
            entry = summary.get(key)
            if entry is None:
                entry = {
                    "device": key[0],
                    "protocol": key[1],
                    "compliance_issue": finding.get("compliance_issue"),
                    "unencrypted": not finding.get("has_crypto"),
                    "observations": 0,
                    "first_source": {"file": src.get("file_path"), "line": src.get("line")},
                    "last_source": {"file": src.get("file_path"), "line": src.get("line")},
                }
                summary[key] = entry
            entry["observations"] += 1
            entry["last_source"] = {"file": src.get("file_path"), "line": src.get("line")}
        observation_summary = sorted(
            summary.values(), key=lambda row: (-row["observations"], row["device"], row["protocol"])
        )
        return {
            "scan_id": scan_id,
            "mode": self.mode,
            "packets_sent": self.packets_emitted,
            "devices": device_rows,
            "findings": findings,
            "device_count": len(devices),
            "unencrypted": len(unencrypted),
            "risk_report": build_ot_posture(findings=findings, devices=device_rows),
            "ot_telemetry": build_ot_telemetry(records=len(records), findings=findings, devices=device_rows),
            "zones": derive_zones(findings),
            "observation_summary": observation_summary,
            "warning": "OT findings are PASSIVE OBSERVATIONS. Confidence: MEDIUM.",
        }

    def _vendor(self, record: dict[str, Any]) -> str | None:
        if record.get("vendor"):
            return str(record["vendor"])
        mac = str(record.get("mac_address") or record.get("mac") or "")
        prefix = ":".join(mac.upper().split(":")[:3])
        if prefix in OUI:
            return OUI[prefix]
        product = str(record.get("product") or record.get("application_uri") or "")
        for name in ("Siemens", "ABB", "Schneider", "Rockwell", "Allen-Bradley"):
            if name.lower() in product.lower():
                return name
        return None

    def _guess_type(self, protocol: str) -> str:
        if protocol.startswith("OPC"):
            return "PLC"
        if protocol.startswith("DNP"):
            return "RTU"
        if "Modbus" in protocol:
            return "PLC"
        if "EtherNet" in protocol or "PROFINET" in protocol:
            return "PLC"
        if protocol.startswith("IEC-104"):
            return "RTU"
        if protocol == "MQTT":
            return "GATEWAY"
        return "OT"


def lookup_cves(device: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    vendor = str(device.get("vendor") or "")
    model = str(device.get("model") or device.get("product") or "")
    version = str(device.get("firmware_version") or "")
    for row in CVE_TABLE:
        if row["vendor"].lower() not in vendor.lower() and row["vendor"].lower() not in model.lower():
            continue
        if row["product"].lower() not in model.lower():
            continue
        if version and _version_lt(version, row["max_exclusive"]):
            hits.append({"cve": row["cve"], "cvss": row["cvss"], "summary": row["summary"]})
    return hits


def _version_lt(current: str, exclusive_max: str) -> bool:
    def parts(value: str) -> list[int]:
        nums = re.findall(r"\d+", value)
        return ([int(item) for item in nums[:3]] + [0, 0, 0])[:3]

    return parts(current) < parts(exclusive_max)


# Re-export so tests can import from the scanner module.
__all__ = ["OtPassiveScanner", "OtSafetyError", "forbid", "lookup_cves", "send_packet"]

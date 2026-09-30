"""Deeper bounded metadata fixtures for WASM and mobile packages."""

import io
import plistlib
import struct
import zipfile

from devsecops import binary_scan as bs


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _name(value: str) -> bytes:
    encoded = value.encode()
    return _uleb(len(encoded)) + encoded


def _wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb(len(payload)) + payload


def _wasm_fixture() -> bytes:
    imports = (_uleb(1) + _name("env") + _name("SSL_connect") + bytes([0]) + _uleb(0))
    exports = _uleb(1) + _name("encrypt") + bytes([0]) + _uleb(0)
    memory = _uleb(1) + bytes([0]) + _uleb(1)
    producers = _name("producers") + _uleb(1) + _name("language") + _uleb(1) + _name("Rust")
    return b"\x00asm\x01\x00\x00\x00" + b"".join((
        _wasm_section(0, producers), _wasm_section(2, imports),
        _wasm_section(5, memory), _wasm_section(7, exports)))


def _android_string_pool(strings: list[str]) -> bytes:
    blob = bytearray()
    offsets = []
    for value in strings:
        offsets.append(len(blob))
        raw = value.encode()
        blob.extend(_uleb(len(value)) + _uleb(len(raw)) + raw + b"\x00")
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(blob)
    header = struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0,
                         0x100, strings_start, 0)
    return header + b"".join(struct.pack("<I", offset) for offset in offsets) + blob


def _android_start_element(name_index: int, attr_name: int, attr_value: int) -> bytes:
    attr_ext = struct.pack("<IIHHHHHH", 0, name_index, 20, 20, 1, 0, 0, 0)
    attr = struct.pack("<IIIHBBI", 0, attr_name, attr_value, 8, 0, 3, attr_value)
    size = 16 + len(attr_ext) + len(attr)
    return struct.pack("<HHIII", 0x0102, 16, size, 1, 0) + attr_ext + attr


def _android_manifest_fixture() -> bytes:
    strings = ["manifest", "package", "com.example.payments"]
    pool = _android_string_pool(strings)
    element = _android_start_element(0, 1, 2)
    total = 8 + len(pool) + len(element)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + element


def test_wasm_parser_extracts_capabilities_without_execution():
    record = bs.parse_bytes(_wasm_fixture(), name="module.wasm")
    assert record["format"] == "wasm"
    assert "env.SSL_connect" in record["imports"]
    assert record["exports"] == ["encrypt"]
    assert record["wasm"]["memory"][0]["minimum"] == 1
    assert "language=Rust" in record["wasm"]["producers"]
    assert record["wasm"]["truncated"] is False


def test_wasm_parser_fails_closed_on_truncated_section():
    record = bs.parse_bytes(b"\x00asm\x01\x00\x00\x00\x02\x80", name="broken.wasm")
    assert record["format"] == "wasm"
    assert record["wasm"]["truncated"] is True
    assert record["wasm"].get("parse_error")


def test_android_manifest_metadata_is_inventory_only(tmp_path):
    package = tmp_path / "payments.apk"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", _android_manifest_fixture())
        archive.writestr("classes.dex", b"dex\n035\x00" + bytes(112))
    record = bs.parse_bytes(package.read_bytes(), name=package.name)
    manifest = record["android"]["manifest"]
    assert record["type"] == "android-package"
    assert manifest["package"] == "com.example.payments"
    assert manifest["permissions"] == []


def test_ipa_info_plist_metadata_is_bounded_and_redacted(tmp_path):
    package = tmp_path / "payments.ipa"
    info = {"CFBundleIdentifier": "com.example.payments", "CFBundleVersion": "7",
            "MinimumOSVersion": "16.0", "SecretToken": "must-not-be-exported"}
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("Payload/Payments.app/Info.plist", plistlib.dumps(info))
    record = bs.parse_bytes(package.read_bytes(), name=package.name)
    plist = record["ios"]["info_plist"]
    assert record["type"] == "ios-package"
    assert plist["CFBundleIdentifier"] == "com.example.payments"
    assert "SecretToken" not in plist


def test_mobile_manifest_policy_observations_are_findings_not_runtime_claims():
    record = {
        "format": "zip", "path": "payments.apk", "crypto": {},
        "android": {"manifest": {
            "debuggable": "true", "usesCleartextTraffic": "true",
            "components": [{"type": "activity", "name": "Main", "exported": "true"}],
        }},
    }
    findings = bs._binary_findings(record)
    codes = {row["code"] for row in findings}
    assert {"BIN-ANDROID-DEBUGGABLE", "BIN-ANDROID-CLEARTEXT",
            "BIN-ANDROID-EXPORTED-COMPONENT"}.issubset(codes)
    assert all(row["path"] == "payments.apk" for row in findings
               if row["code"].startswith("BIN-ANDROID"))

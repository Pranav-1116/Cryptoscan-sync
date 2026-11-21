"""Cryptava unit tests — the standard library and pytest only."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import fakehost  # noqa: E402
from cryptava import cli  # noqa: E402
from cryptava.agent import build_payload, collect  # noqa: E402
from cryptava.collectors.crypto import ssh_key_facts  # noqa: E402
from cryptava.collectors.software import parse_apk_installed, parse_dpkg_status  # noqa: E402
from cryptava.config import ConfigError, load_config  # noqa: E402
from cryptava.observation import Observation, state_hash  # noqa: E402
from cryptava.signing import SigningKey, canonical_bytes, signed_document, verify  # noqa: E402
from cryptava.util import CommandRefused, run_allowed  # noqa: E402
from cryptava.x509 import certificates_in, parse_der  # noqa: E402

PLANES = {"HBOM", "SBOM", "NBOM", "CBOM", "VBOM", "TechBOM"}


@pytest.fixture()
def host(tmp_path):
    config = load_config(env={})
    config.update(fakehost.build(tmp_path / "h"))
    config["tags"] = {"environment": "prod", "datacenter": "dc1"}
    config["system"] = {"name": "SWIFT Gateway", "applications": [{"name": "Alliance Access", "services": ["nginx"]}]}
    return config


def _by_type(payload, kind):
    return [a for a in payload["assets"] if a["type"] == kind]


def _facts(payload, target):
    return [e["facts"] for e in payload["evidence"] if e["target"] == target]


# --------------------------------------------------------------------------- #
# signing
# --------------------------------------------------------------------------- #

def test_ed25519_matches_rfc8032_vector():
    key = SigningKey(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    assert key.public_raw.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    signature = key.sign(b"")
    assert signature.hex().startswith("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249")
    assert verify(key.public_raw, b"", signature)
    assert not verify(key.public_raw, b"tampered", signature)


def test_key_file_is_pkcs8_and_private(tmp_path):
    key = SigningKey.generate()
    path = tmp_path / "agent.key"
    key.save(path)
    assert (path.stat().st_mode & 0o777) == 0o600
    assert path.read_text().startswith("-----BEGIN PRIVATE KEY-----")
    assert SigningKey.load(path).public_raw == key.public_raw


def test_signature_covers_exactly_the_platform_document(host):
    key = SigningKey.generate()
    payload = build_payload(collect(host), host, contributor="mrdn-prod-dc1-swiftgw01", key=key)
    block = payload["signature"]
    document = signed_document(payload)
    assert document["contributor"] == "mrdn-prod-dc1-swiftgw01"
    assert "state_hash" not in document and "signature" not in document
    assert verify(base64.b64decode(block["public_key"]), canonical_bytes(document),
                  base64.b64decode(block["signature"]))
    # any change to what was observed breaks it
    document["assets"] = document["assets"][1:]
    assert not verify(base64.b64decode(block["public_key"]), canonical_bytes(document),
                      base64.b64decode(block["signature"]))


def test_canonical_form_matches_shared_models_when_available():
    shared = HERE.parents[2] / "shared" / "shared_models"
    sys.path.insert(0, str(shared))
    try:
        from shared_models import release_signature  # type: ignore
    except Exception:  # pragma: no cover — the agent's own CI has no platform checkout
        pytest.skip("platform shared_models not importable")
    document = {"b": [1, {"z": "é", "a": None}], "a": "x", "signature": {"drop": True}}
    assert canonical_bytes(document) == release_signature.canonical_bytes(document)


# --------------------------------------------------------------------------- #
# the whole host
# --------------------------------------------------------------------------- #

def test_fake_host_reports_all_six_planes(host):
    ctx = collect(host)
    payload = build_payload(ctx, host, contributor="mrdn-prod-dc1-swiftgw01", key=None)
    planes = {row["plane"].split(" ")[0]: row for row in payload["collectors"]}
    assert set(planes) == PLANES
    assert all(row["status"] in {"COMPLETE", "PARTIAL"} for row in planes.values()), planes
    assert payload["schema"] == "cryptoscan.live-observation/1"
    assert payload["contributor"] == "mrdn-prod-dc1-swiftgw01"
    assert payload["state_hash"] == state_hash(payload)

    host_asset = _by_type(payload, "HOST")[0]
    assert host_asset["identity"]["hostname"] == "swiftgw01.mrdn.bank"
    assert host_asset["identity"]["ip_address"] == "10.210.0.4"

    # HBOM
    hardware = {a["ref"] for a in _by_type(payload, "HARDWARE")}
    assert {"hw:system", "hw:cpu", "hw:tpm"} <= hardware
    system = next(a for a in payload["assets"] if a["ref"] == "hw:system")
    assert system["identity"]["serial_number"] == "7XK2M93"
    cpu_facts = json.dumps(_facts(payload, "hw:cpu"))
    assert "AES-NI" in cpu_facts and "SHA-NI" in cpu_facts
    assert _by_type(payload, "FIRMWARE")

    # SBOM — the deinstalled package is not reported; Python and Java are
    packages = {(a["identity"]["name"], a["identity"]["ecosystem"]) for a in _by_type(payload, "PACKAGE")}
    assert ("libssl3", "deb") in packages and ("requests", "pypi") in packages
    assert ("bcprov-jdk18on", "maven") in packages
    assert not any(name == "removed-thing" for name, _ in packages)

    # NBOM — listener owned by nginx, outbound peer, endpoint identity
    endpoints = {a["identity"]["port"]: a for a in _by_type(payload, "NETWORK_ENDPOINT")}
    assert endpoints["8443"]["attributes"]["process"] == "nginx"
    assert endpoints["1792"]["identity"]["host"] == "10.210.0.11"
    edges = {(r["subject"], r["predicate"], r["object"]) for r in payload["relationships"]}
    assert ("svc:nginx", "exposes", endpoints["8443"]["ref"]) in edges
    assert ("svc:nginx", "connects_to", endpoints["1792"]["ref"]) in edges

    # CBOM — library owned by a package and loaded by nginx; CA-issued cert; SSH; config
    libraries = _by_type(payload, "LIBRARY")
    libssl = next(a for a in libraries if a["attributes"]["path"].endswith("libssl.so.3"))
    assert libssl["identity"]["version"] == "3.0.15"
    assert libssl["attributes"]["package"] == "libssl3"
    assert ("svc:nginx", "uses_crypto_library", libssl["ref"]) in edges
    cert = _by_type(payload, "CERTIFICATE")[0]
    assert cert["identity"]["fingerprint_sha256"].startswith("0c81bc904608ee1f")
    ca = _by_type(payload, "CA")[0]
    assert (cert["ref"], "issued_by", ca["ref"]) in edges
    assert ("svc:nginx", "uses_certificate", cert["ref"]) in edges
    cert_facts = _facts(payload, cert["ref"])
    assert any(f.get("algorithm") == "ECDSA" and f.get("curve") == "P-256" for f in cert_facts)
    assert any(f.get("algorithm") == "SHA256withRSA" for f in cert_facts)
    ssh = _by_type(payload, "KEY_METADATA")[0]
    assert ssh["attributes"]["algorithm"] == "Ed25519"
    sshd_config = json.dumps(_facts(payload, "svc:sshd"))
    assert "sntrup761x25519-sha512@openssh.com" in sshd_config
    nginx_config = json.dumps(_facts(payload, "svc:nginx"))
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" in nginx_config and "TLSv1.2" in nginx_config

    # VBOM
    vendors = {a["identity"]["name"] for a in _by_type(payload, "VENDOR")}
    assert {"Dell Technologies", "Intel", "Debian Project", "OpenSSL Software Foundation", "Meridian Bank"} <= vendors
    debian = next(a for a in _by_type(payload, "VENDOR") if "operating system" in a["identity"]["product"])
    assert any(f.get("support_end") == "2028-06-30" for f in _facts(payload, debian["ref"]))

    # TechBOM
    system_node = _by_type(payload, "SYSTEM")[0]
    assert system_node["name"] == "SWIFT Gateway"
    assert ("host", "part_of", system_node["ref"]) in edges


def test_every_edge_cites_evidence_that_exists(host):
    payload = build_payload(collect(host), host, contributor=None, key=None)
    refs = {e["ref"] for e in payload["evidence"]}
    assets = {a["ref"] for a in payload["assets"]}
    for edge in payload["relationships"]:
        assert edge["evidence_refs"] and set(edge["evidence_refs"]) <= refs, edge
        assert edge["subject"] in assets and edge["object"] in assets
    for record in payload["evidence"]:
        assert record["target"] in assets


def test_private_keys_never_leave_the_host(host):
    payload = json.dumps(build_payload(collect(host), host, contributor=None, key=None))
    assert "not-a-real-key" not in payload and "never-read" not in payload
    assert "PRIVATE KEY" not in payload


def test_a_broken_plane_is_reported_not_hidden(host, monkeypatch):
    from cryptava.collectors import network

    def boom(ctx):
        raise RuntimeError("socket table unreadable")

    monkeypatch.setattr(network, "collect", boom)
    payload = build_payload(collect(host), host, contributor=None, key=None)
    planes = {row["plane"].split(" ")[0]: row for row in payload["collectors"]}
    assert planes["NBOM"]["status"] == "FAILED" and "socket table unreadable" in planes["NBOM"]["reason"]
    assert planes["CBOM"]["status"] in {"COMPLETE", "PARTIAL"}


# --------------------------------------------------------------------------- #
# parsers and guards
# --------------------------------------------------------------------------- #

def test_x509_parses_the_issued_certificate():
    ders = certificates_in((HERE / "fixtures" / "leaf.pem").read_bytes())
    cert = parse_der(ders[0])
    assert cert["subject_cn"] == "swiftgw01.mrdn.bank"
    assert cert["issuer_cn"] == "Meridian Issuing CA 1"
    assert cert["public_key_algorithm"] == "ECDSA" and cert["curve"] == "P-256"
    assert cert["signature_algorithm"] == "sha256WithRSAEncryption"
    assert "swiftgw01.mrdn.bank" in json.dumps(cert["san"]) and not cert["self_signed"]
    ca = parse_der(certificates_in((HERE / "fixtures" / "ca.pem").read_bytes())[0])
    assert ca["is_ca"] and ca["self_signed"] and ca["public_key_bits"] == 2048


def test_package_database_parsers():
    rows = parse_dpkg_status(fakehost.DPKG_STATUS)
    assert {r["name"] for r in rows} == {"libssl3", "openssl", "nginx", "openssh-server"}
    packages, owners = parse_apk_installed(
        "P:libcrypto3\nV:3.3.2-r0\nA:x86_64\no:openssl\nF:usr/lib\nR:libcrypto.so.3\n\n"
        "P:musl\nV:1.2.5-r0\nF:lib\nR:ld-musl-x86_64.so.1\n")
    assert packages[0]["version"] == "3.3.2-r0" and owners["/usr/lib/libcrypto.so.3"] == "libcrypto3"


def test_ssh_key_facts():
    facts = ssh_key_facts(fakehost.SSH_ED25519_PUB)
    assert facts["algorithm"] == "Ed25519" and facts["fingerprint"].startswith("SHA256:")
    assert ssh_key_facts("not a key") is None


def test_observation_refuses_an_edge_without_evidence():
    obs = Observation()
    obs.asset("a", "HOST", "a", identity={"hostname": "a"})
    obs.asset("b", "HARDWARE", "b", identity={"model": "b"})
    with pytest.raises(ValueError):
        obs.relate("a", "hosted_on", "b", basis="RUNTIME_OBSERVATION", evidence=[])
    with pytest.raises(ValueError):
        obs.relate("a", "hosted_on", "b", basis="RUNTIME_OBSERVATION", evidence=["ev-missing"])
    with pytest.raises(ValueError):
        obs.asset("c", "NOT_A_TYPE", "c", identity={})


def test_only_allowlisted_commands_run():
    with pytest.raises(CommandRefused):
        run_allowed(["bash", "-c", "id"])
    with pytest.raises(CommandRefused):
        run_allowed(["rpm", "-e", "openssl"])
    with pytest.raises(CommandRefused):
        run_allowed(["dmidecode", "-t", "system;reboot"])


def test_config_environment_overrides(tmp_path):
    path = tmp_path / "cryptava.json"
    path.write_text(json.dumps({"server": "https://console.bank/", "interval": 900}))
    config = load_config(str(path), env={"CRYPTAVA_INTERVAL": "300", "CRYPTAVA_TAGS": '{"environment": "uat"}',
                                         "CRYPTAVA_PROBE_LISTENERS": "false"})
    assert config["server"] == "https://console.bank" and config["interval"] == 300
    assert config["tags"] == {"environment": "uat"} and config["probe_listeners"] is False
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "missing.json"), env={})


def test_cli_collect_writes_the_observation(host, tmp_path, capsys):
    config_path = tmp_path / "c.json"
    config_path.write_text(json.dumps({k: v for k, v in host.items() if not k.startswith("_")}))
    out = tmp_path / "obs.json"
    code = cli.main(["collect", "--config", str(config_path), "--state-dir", str(tmp_path / "s"),
                     "--output", str(out)])
    assert code == 0
    assert "SBOM" in capsys.readouterr().out
    assert json.loads(out.read_text())["schema"] == "cryptoscan.live-observation/1"
    assert cli.main(["run", "--once", "--config", str(config_path), "--state-dir", str(tmp_path / "s")]) == 4
    os.environ.pop("CRYPTAVA_CONFIG", None)


def _payload(config):
    return build_payload(collect(config), config, contributor="t", key=None)


def test_symlinked_openssl_cnf_is_counted_once(host):
    root = Path(host["root"])
    target = root / "usr/lib/ssl/openssl.cnf"
    target.parent.mkdir(parents=True, exist_ok=True)
    os.symlink("/etc/ssl/openssl.cnf", target)  # Debian layout, absolute target
    # only the HOST copy carries these values; reading the agent's own /etc would not
    (root / "etc/ssl/openssl.cnf").write_text(
        "[system_default_sect]\nMinProtocol = TLSv1.3\nCipherString = DEFAULT@SECLEVEL=3\n")
    payload = _payload(host)
    settings = [f for e in payload["evidence"] for f in [e["facts"]]
                if e.get("source") == "cryptava-opensslcnf" or f.get("role", "").startswith("system-")]
    assert sum(1 for f in settings if f.get("role") == "system-minimum-protocol") == 1
    assert sum(1 for f in settings if f.get("setting") == "CipherString") == 1
    assert [f["protocol"] for f in settings if f.get("role") == "system-minimum-protocol"] == ["TLSv1.3"]


def test_host_reads_follow_absolute_symlinks_inside_the_host_root(host):
    from cryptava.agent import host_view

    root = Path(host["root"])
    (root / "srv/tls").mkdir(parents=True, exist_ok=True)
    (root / "srv/tls/policy.txt").write_text("host copy")
    os.symlink("/srv/tls/policy.txt", root / "etc/policy-link")
    view = host_view(host)
    assert view.read_text("/etc/policy-link") == "host copy"
    assert view.exists("/etc/policy-link")


def test_openssl_library_defaults_are_reported_as_a_fact(host):
    root = Path(host["root"])
    (root / "etc/ssl/openssl.cnf").write_text("openssl_conf = openssl_init\n[openssl_init]\n")
    payload = _payload(host)
    facts = [e["facts"] for e in payload["evidence"]]
    assert any(f.get("setting") == "OpenSSL system TLS policy" for f in facts)
    cbom = next(p for p in payload["collectors"] if p["plane"].startswith("CBOM"))
    assert "OpenSSL library defaults" in cbom["reason"]


def test_a_process_that_exits_mid_scan_is_not_an_access_gap(host, monkeypatch):
    from cryptava.util import HostView

    real = HostView.proc_text_or_reason

    def flaky(self, relative, **kw):
        if relative.endswith("/maps"):
            return None, "gone"
        return real(self, relative, **kw)

    monkeypatch.setattr(HostView, "proc_text_or_reason", flaky)
    payload = _payload(host)
    cbom = next(p for p in payload["collectors"] if p["plane"].startswith("CBOM"))
    assert cbom["status"] == "COMPLETE" and "not readable" not in cbom["reason"]


def test_distinct_ipv6_listeners_get_distinct_refs():
    from cryptava.collectors.network import _host_slug

    assert _host_slug("1::2:3") != _host_slug("1:2::3")
    assert _host_slug("10.210.0.4") == "10-210-0-4"  # IPv4 refs unchanged


# --------------------------------------------------------------------------- #
# asset register: HBOM identity where firmware is hidden, VBOM contracts
# --------------------------------------------------------------------------- #

import shutil  # noqa: E402
from datetime import date, timedelta  # noqa: E402

REPO = HERE.parents[2]
SOURCE_STATES = {"READ", "EMPTY", "ABSENT", "DENIED", "UNAVAILABLE", "DISABLED", "NOT_CONFIGURED"}


def _plane(payload, key):
    return next(p for p in payload["collectors"] if p["plane"].split(" ")[0] == key)


def _no_dmi(host):
    shutil.rmtree(Path(host["sys"]) / "class/dmi", ignore_errors=True)


def _record(tmp_path, **data):
    path = tmp_path / "asset-record.json"
    path.write_text(json.dumps({"source": "Test CMDB", "exported_at": "2026-11-01", **data}))
    return str(path)


HARDWARE = {"manufacturer": "Dell Technologies", "model": "PowerEdge R750", "serial_number": "7Q2K3X3",
            "asset_tag": "MRDN-DC1-000412", "location": "DC1 / Rack 04", "warranty_end": "2099-01-01"}


def test_hbom_without_firmware_or_register_is_partial_and_says_what_to_supply(host):
    _no_dmi(host)
    hbom = _plane(_payload(host), "HBOM")
    assert hbom["status"] == "PARTIAL"
    assert "no asset-register hardware record" in hbom["reason"]
    assert "/etc/cryptava/asset-record.json" in hbom["reason"]
    states = {s["source"]: s["state"] for s in hbom["sources"]}
    assert states["/sys/class/dmi/id"] == "ABSENT"
    assert states["/etc/cryptava/asset-record.json"] == "NOT_CONFIGURED"


def test_hbom_identity_from_the_asset_register_is_complete_and_marked_imported(host, tmp_path):
    _no_dmi(host)
    host["asset_record"] = _record(tmp_path, hardware=HARDWARE)
    payload = _payload(host)
    hbom = _plane(payload, "HBOM")
    assert hbom["status"] == "COMPLETE", hbom["reason"]
    assert "asset register (Test CMDB)" in hbom["reason"]
    system = next(a for a in payload["assets"] if a["ref"] == "hw:system")
    assert system["name"] == "Dell Technologies PowerEdge R750"
    assert system["identity"]["serial_number"] == "7Q2K3X3"
    assert system["attributes"]["identity_source"] == "asset register"
    assert system["attributes"]["warranty_state"] == "IN_WARRANTY"
    imported = [e for e in payload["evidence"] if e["target"] == "hw:system" and e["evidence_type"] == "IMPORTED"]
    assert imported and imported[0]["facts"]["source"] == "Test CMDB"
    # the vendor edge from a register entry is IMPORTED, not observed
    edge = next(r for r in payload["relationships"] if r["subject"] == "hw:system" and r["predicate"] == "provided_by")
    assert edge["basis"] == "IMPORTED"


def test_hbom_register_and_firmware_disagreeing_is_reported_not_resolved(host, tmp_path):
    host["asset_record"] = _record(tmp_path, hardware={**HARDWARE, "serial_number": "NOT-THE-SAME"})
    payload = _payload(host)
    hbom = _plane(payload, "HBOM")
    assert hbom["status"] == "COMPLETE"
    assert "differs from firmware serial" in hbom["reason"]
    assert any(e["facts"].get("role") == "asset-register-mismatch" for e in payload["evidence"])
    system = next(a for a in payload["assets"] if a["ref"] == "hw:system")
    assert system["attributes"]["identity_source"] == "firmware (DMI)"


def test_hbom_in_a_container_does_not_expect_dimm_layout(host, tmp_path, monkeypatch):
    _no_dmi(host)
    (Path(host["root"]) / ".dockerenv").write_text("")
    host["dmidecode"] = True
    host["asset_record"] = _record(tmp_path, hardware=HARDWARE)
    from cryptava.collectors import hardware
    from cryptava.util import CommandResult
    monkeypatch.setattr(hardware, "run_allowed",
                        lambda *a, **k: CommandResult(("dmidecode",), 127, b"", "dmidecode: not installed", available=False))
    hbom = _plane(_payload(host), "HBOM")
    assert hbom["status"] == "COMPLETE", hbom["reason"]
    assert "inside a container" in hbom["reason"]
    assert {s["source"]: s["state"] for s in hbom["sources"]}["dmidecode -t memory"] == "UNAVAILABLE"


def test_vbom_without_a_contract_register_is_partial(host):
    vbom = _plane(_payload(host), "VBOM")
    assert vbom["status"] == "PARTIAL"
    assert "asset-register record" in vbom["reason"]


def test_vbom_contracts_are_matched_to_observed_vendors_with_a_state(host, tmp_path):
    today = date.today()
    host["asset_record"] = _record(tmp_path, contracts=[
        {"vendor": "OpenSSL Software Foundation", "contract_id": "OSF-1", "support_level": "Premium",
         "end": (today + timedelta(days=30)).isoformat()},
        {"vendor": "Debian Project", "support_level": "community"},
        {"vendor": "Meridian Bank", "support_level": "internal"},
        {"vendor": "Dell Technologies", "contract_id": "PSP-1", "end": (today - timedelta(days=1)).isoformat(),
         "covers": ["Intel"]},
        {"vendor": "Oracle", "contract_id": "never-seen"},
    ])
    payload = _payload(host)
    vbom = _plane(payload, "VBOM")
    assert vbom["status"] == "COMPLETE", vbom["reason"]
    assert "1 register entry names a vendor not seen on this host" in vbom["reason"]
    vendors = {a["identity"]["name"]: a for a in payload["assets"] if a["type"] == "VENDOR"}
    states = {name: a["attributes"].get("contract_state") for name, a in vendors.items()}
    assert states["OpenSSL Software Foundation"] == "EXPIRING_SOON"
    assert states["Debian Project"] == "COMMUNITY"
    assert states["Intel"] == "EXPIRED"            # covered by the (lapsed) OEM contract
    assert "Oracle" not in vendors                 # a register entry never invents a vendor
    assert all(state for state in states.values())  # every vendor has a state, NONE_ON_RECORD included
    contract_ev = [e for e in payload["evidence"] if e["facts"].get("record") == "vendor-contract"]
    assert contract_ev and all(e["evidence_type"] == "IMPORTED" for e in contract_ev)
    assert any(e["facts"].get("contract_id") == "OSF-1" for e in contract_ev)


def test_inline_contracts_from_the_environment(tmp_path):
    config = load_config(env={"CRYPTAVA_CONTRACTS": '[{"vendor": "Red Hat", "contract_id": "RH-1"}]',
                              "CRYPTAVA_HARDWARE": '{"manufacturer": "HPE", "model": "DL380", "asset_tag": "A1"}'})
    from cryptava.register import load
    reg = load(config)
    assert reg.state == "READ" and reg.has_contract_register and reg.hardware_identified()
    assert reg.contracts[0]["contract_id"] == "RH-1"


def test_every_plane_reports_how_it_was_collected(host):
    payload = _payload(host)
    assert {p["plane"].split(" ")[0] for p in payload["collectors"]} == PLANES
    for plane in payload["collectors"]:
        assert plane.get("sources"), plane["plane"]
        for row in plane["sources"]:
            assert row["state"] in SOURCE_STATES and row["source"] and row["reads"]


def test_sandbox_asset_records_cover_every_bank_server():
    records = sorted((REPO / "sandbox/cryptava").glob("*.json"))
    hosts = {p.stem for p in records}
    assert hosts == {"internet-banking", "mobile-api", "swift-gateway", "legacy-branch", "hsm-sim",
                     "core-banking-db", "payments-bastion"}
    from cryptava.register import Register
    for path in records:
        reg = Register(json.loads(path.read_text()), str(path), "READ")
        assert reg.hardware_identified(), path.name
        assert reg.has_contract_register and reg.contracts, path.name
    compose = (REPO / "sandbox/docker-compose.sandbox.yml").read_text()
    for host in hosts:  # every bank server has a built-in agent with its CMDB record
        assert f"container_name: cryptoscan-cryptava-{host}\n" in compose, host
        assert f'network_mode: "service:{host}"' in compose, host
        assert f"./sandbox/cryptava/{host}.json:/etc/cryptava/asset-record.json:ro" in compose, host
    names = re.findall(r'CRYPTAVA_NAME: "([^"]+)"', compose)
    assert len(names) == 7 and len(set(names)) == 7
    runner = (REPO / "sandbox/run_sandbox.sh").read_text()
    for host in hosts:
        assert re.search(rf"\n\s+{re.escape(host)}\)\s+echo \"cryptoscan-sbx-", runner), host
        assert host in runner.split('SBX_HOSTS="', 1)[1].split('"', 1)[0], host


def test_brief_status_says_whether_the_agent_is_connected():
    from cryptava.cli import brief_status

    assert brief_status(None, None).startswith("NOT ENROLLED")
    identity = {"name": "mrdn-sbx-dc1-hsmsim01", "server": "http://api:8010"}
    assert brief_status(identity, None).startswith("ENROLLED")
    ok = {"delivered": True, "response": {"authenticity": "VALID"},
          "summary": {"observed_at": "2026-11-19T07:00:00+00:00",
                      "planes": [{"plane": "HBOM · hardware", "status": "COMPLETE"}]}}
    line = brief_status(identity, ok)
    assert line.startswith("CONNECTED") and "signature verified" in line and "HBOM:complete" in line
    down = brief_status(identity, {"delivered": False, "error": "cannot reach http://api:8010", "summary": {}})
    assert down.startswith("NOT DELIVERED") and "cannot reach" in down


def test_declared_system_dependencies_are_approved_mapping_edges(host):
    host["system"] = {"name": "SWIFT Gateway", "criticality": "tier-0",
                      "depends_on": [{"name": "Core Banking", "via": "ISO 20022 over TLS"}, "Payment HSM",
                                     "SWIFT Gateway", ""]}
    payload = build_payload(collect(host), host, contributor=None, key=None)
    systems = {a["name"]: a["ref"] for a in _by_type(payload, "SYSTEM")}
    assert set(systems) == {"SWIFT Gateway", "Core Banking", "Payment HSM"}
    edges = [r for r in payload["relationships"] if r["predicate"] == "depends_on"
             and r["subject"] == systems["SWIFT Gateway"]]
    assert {r["object"] for r in edges} == {systems["Core Banking"], systems["Payment HSM"]}
    assert all(r["basis"] == "APPROVED_MAPPING" and r["evidence_refs"] for r in edges)
    declared = [f for f in _facts(payload, systems["SWIFT Gateway"]) if f.get("depends_on")]
    assert {f["depends_on"] for f in declared} == {"Core Banking", "Payment HSM"}
    assert any(f.get("via") == "ISO 20022 over TLS" for f in declared)

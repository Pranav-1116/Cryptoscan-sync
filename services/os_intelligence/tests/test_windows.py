"""Windows adapter acceptance tests
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §15 step 9).

PROVENANCE: the fixtures are RECONSTRUCTED from documented Microsoft
output formats (see fixtures/windows/README.md) — they were NOT
captured from a live Windows host. Passing these tests is NOT Windows
fleet qualification (§12). The canonical OS model is shared with the
Linux collector (§15 step 4).
"""

from __future__ import annotations

from pathlib import Path

from os_intelligence.rules import evaluate
from os_intelligence.windows import (collect_windows, parse_csplist,
                                     parse_driverquery, parse_get_tpm,
                                     parse_manage_bde, parse_reg_query,
                                     parse_schannel_protocols,
                                     parse_secureboot, parse_systeminfo,
                                     parse_ver)

WIN = Path(__file__).parent / "fixtures" / "windows"


def _read(name: str) -> str:
    return (WIN / name).read_text()


def _captured() -> dict:
    return {
        "systeminfo": _read("systeminfo.txt"),
        "certutil_csplist": _read("certutil_csplist.txt"),
        "reg_schannel_protocols": _read("reg_schannel.txt"),
        "manage_bde": _read("manage_bde.txt"),
        "get_tpm": _read("get_tpm.txt"),
        "confirm_secureboot": _read("confirm_secureboot.txt"),
        "driverquery": _read("driverquery.txt"),
    }


class TestProvenanceHonesty:
    def test_fixture_provenance_is_labelled(self):
        readme = (WIN / "README.md").read_text()
        assert "RECONSTRUCTED" in readme
        assert "NOT captured from a live Windows host" in readme
        assert "NOT Windows fleet qualification" in readme

    def test_identity_carries_the_qualification_caveat(self):
        inv = collect_windows("win-host", _captured())
        identity = inv["identity"]
        assert identity["environment_development_only"] is True
        assert "enterprise qualification" in identity["qualification_note"]
        assert identity["platform"] == "windows"


class TestIdentity:
    def test_systeminfo_parsing(self):
        fields = parse_systeminfo(_read("systeminfo.txt"))
        assert fields["os_pretty_name"] == \
            "Microsoft Windows Server 2022 Datacenter"
        assert fields["kernel_release"] == "10.0.20348"
        assert fields["build"] == "20348"

    def test_ver_parsing(self):
        assert parse_ver("Microsoft Windows [Version 10.0.20348.1]") == \
            "10.0.20348.1"
        assert parse_ver("garbage") == ""

    def test_missing_identity_never_guessed(self):
        inv = collect_windows("win-host", {})
        assert inv["identity"]["kernel_release"] == "unknown"
        assert any("unknown, never guessed" in n
                   for n in inv["identity"]["notes"])


class TestProviders:
    def test_csp_ksp_registrations_are_inventory_never_usage(self):
        entries, _ = parse_csplist(_read("certutil_csplist.txt"))
        names = {e.name for e in entries}
        assert "Microsoft Software Key Storage Provider" in names
        kinds = {e.name: e.type for e in entries}
        assert kinds["Microsoft Software Key Storage Provider"] == "ksp"
        csp = [e for e in entries
               if "Enhanced RSA and AES" in e.name][0]
        assert csp.type == "csp"
        for e in entries:
            d = e.as_dict()
            assert d["runtime_usage_confirmed"] is False
            assert "not proof of runtime use" in d["note"]

    def test_malformed_provider_block_fail_safe(self):
        entries, _ = parse_csplist("Provider Type: not-a-number\n\n")
        assert entries, "a bare name-less block is preserved honestly"
        for e in entries:
            assert e.priority is None or isinstance(e.priority, int)


class TestSchannelThreeFindings:
    def test_enabled_by_config_axis_only(self):
        inv = collect_windows("win-host", _captured())
        flags = inv["config_flags"]
        assert flags["SCHANNEL\\TLS 1.0\\server\\enabled"] == "disabled"
        assert flags["SCHANNEL\\TLS 1.0\\client\\enabled"] == "enabled"
        assert flags["SCHANNEL\\TLS 1.2\\server\\enabled"] == "enabled"
        assert "ENABLED-BY-CONFIG" in flags["__tls_axis__"]
        assert "NOT established by this source" in flags["__tls_axis__"]

    def test_006_fires_with_the_spec_example_format(self):
        inv = collect_windows("win-host", _captured())
        report = evaluate(inv)
        rule = [r for r in report.results
                if r.rule_id == "OS-CRYPTO-006"][0]
        assert rule.status == "evaluated"
        protocols = {f["details"]["configured_protocol"]
                     for f in rule.findings}
        assert "TLS 1.0" in protocols   # client side enabled
        assert "SSL 3.0" in protocols   # server side enabled
        assert "TLS 1.2" not in protocols, \
            "TLS 1.2 enabled is not a weak-protocol finding"
        for f in rule.findings:
            d = f["details"]
            assert d["observed_runtime_negotiation"] == "Not established"
            assert d["affected_service"] == "Requires correlation"
            assert d["business_system"] == "Requires registered mapping"
            assert "ENABLED-BY-CONFIG axis only" in str(f["limitations"])

    def test_006_not_detected_is_never_absent(self):
        inv = collect_windows("win-host", _captured())
        inv["config_flags"] = {
            k: ("disabled"
                if (k.startswith("SCHANNEL\\")
                    and k.lower().split("\\")[1] in
                    ("tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0")
                    and k.lower().endswith("\\enabled"))
                else v)
            for k, v in inv["config_flags"].items()}
        rule = [r for r in evaluate(inv).results
                if r.rule_id == "OS-CRYPTO-006"][0]
        assert rule.status == "evaluated"
        assert rule.findings == []
        assert "never 'absent'" in rule.evaluation_note

    def test_reg_query_not_configured_vs_disabled(self):
        reg, _ = parse_reg_query(
            "HKEY_LOCAL_MACHINE\\X\\Protocols\\TLS 1.0\\Server\n"
            "    Enabled    REG_DWORD    0x0\n\n"
            "HKEY_LOCAL_MACHINE\\X\\Protocols\\TLS 1.1\\Server\n")
        flags, _ = parse_schannel_protocols(reg)
        assert flags["SCHANNEL\\TLS 1.0\\server\\enabled"] == "disabled"
        assert "SCHANNEL\\TLS 1.1\\server\\enabled" not in flags, \
            "a key with no value line is not a recorded state (§2.1)"


class TestStorageAndTrust:
    def test_bitlocker_metadata_never_key_material(self):
        facts, _ = parse_manage_bde(_read("manage_bde.txt"))
        assert len(facts) == 2
        c = facts[0]
        assert c.metadata["conversion_status"] == "Fully Encrypted"
        assert c.metadata["encryption_method"] == "XTS-AES 256"
        assert "no recovery password" in c.notes[0]
        d = facts[1]
        assert any("never a security verdict" in n for n in d.notes)

    def test_007_never_calls_a_fully_encrypted_volume_unestablished(self):
        inv = collect_windows("win-host", _captured())
        rule = [r for r in evaluate(inv).results
                if r.rule_id == "OS-CRYPTO-007"][0]
        devices = [f["details"]["device"] for f in rule.findings]
        assert not any("Windows" in d for d in devices), \
            "a Fully Encrypted BitLocker volume is ESTABLISHED"
        assert any("Data" in d for d in devices), \
            "the Fully Decrypted volume is honestly unestablished"

    def test_tpm_presence_is_metadata_never_a_verdict(self):
        fact, _ = parse_get_tpm(_read("get_tpm.txt"))
        assert fact.state == "present"
        assert "never a trust verdict" in fact.notes[0]

    def test_tpm_error_is_unavailable_never_no_tpm(self):
        fact, _ = parse_get_tpm(
            "Get-Tpm : Access is denied. (Exception from HRESULT: "
            "0x80070005)")
        assert fact is None
        inv = collect_windows("win-host", {"get_tpm": {"error":
                                                       "permission_denied"}})
        tpm = [t for t in inv["hardware_trust"]
               if t["subject"] == "tpm"][0]
        assert tpm["state"] == "unavailable"
        assert tpm["evidence_class"] == "unknown"
        assert any("never as 'no TPM'" in n for n in tpm["notes"])

    def test_secureboot_false_is_a_state_unavailable_is_not(self):
        assert parse_secureboot("False").state == "disabled"
        unknown = parse_secureboot("Confirm-SecureBootUEFI : cmdlet "
                                   "not supported on this platform")
        assert unknown.state == "unavailable"
        assert any("NEVER as 'disabled'" in n for n in unknown.notes)


class TestModulesAndCoverage:
    def test_driverquery_fail_safe(self):
        modules = parse_driverquery(_read("driverquery.txt"))
        assert {m.name for m in modules} == {"acpi", "ksecdd"}
        garbage = parse_driverquery("Module Name:     \nRandom line\n")
        assert garbage == [], "rows without names are never fabricated"

    def test_missing_sources_recorded_never_zeros(self):
        inv = collect_windows("win-host", {"systeminfo":
                                           _read("systeminfo.txt")})
        cov = inv["coverage"]
        assert cov["sources_unavailable"], "unavailable sources recorded"
        for entry in cov["sources_unavailable"]:
            assert entry["reason"]
        assert "never treated as" in cov["note"].lower() or \
            "NEVER treated as" in cov["note"]


class TestSharedCanonicalModel:
    def test_windows_inventory_feeds_the_shared_rules(self):
        """§15 step 4: one canonical model — the rule catalogue
        evaluates a Windows collection with platform honesty."""
        inv = collect_windows("win-host", _captured())
        report = evaluate(inv)
        by_id = {r.rule_id: r for r in report.results}
        assert len(report.results) == 18
        # Linux-specific rules are honestly not_evaluable on Windows
        for rule_id in ("OS-CRYPTO-002", "OS-CRYPTO-014",
                        "OS-CRYPTO-016"):
            assert by_id[rule_id].status == "not_evaluable"
            assert "Linux-specific" in by_id[rule_id].evaluation_note
            assert "never clean" in by_id[rule_id].evaluation_note
        # platform-neutral rules evaluate
        assert by_id["OS-CRYPTO-001"].status == "evaluated"
        assert by_id["OS-CRYPTO-006"].status == "evaluated"
        # every finding keeps the decisive field
        for r in report.results:
            for f in r.findings:
                assert f["runtime_usage_confirmed"] is False

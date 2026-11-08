"""OS & Kernel Intelligence Engine — acceptance tests against the
REAL recorded host corpus and the LIVE local Linux configuration
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §12, §15 step 7)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from os_intelligence.collector import collect_linux
from os_intelligence.crypto_api import parse_crypto_api
from os_intelligence.evidence import CoverageReport, OSFinding
from os_intelligence.identity import parse_os_release, parse_taints, \
    parse_uname_line
from os_intelligence.inventory import parse_config_flags, parse_lsblk, \
    parse_modules

FIXTURES = Path(__file__).parent / "fixtures"
HOST_SAMPLE = (FIXTURES / "host-linux-sample.txt").read_text()


def _section(text: str, name: str) -> str:
    return text.split(f"--- {name}")[1].split("\n---")[0]


class TestProcCryptoParser:
    """§2.2: /proc/crypto parser with driver/module/key-size metadata;
    one algorithm with several implementations; entries normalized
    with generic algorithm name distinct from implementation driver."""

    def test_parses_real_host_entries(self):
        entries, notes = parse_crypto_api(_section(HOST_SAMPLE, "proc-crypto"))
        assert entries, "the real host /proc/crypto has entries"
        by_alg = {}
        for e in entries:
            by_alg.setdefault(e.name, []).append(e)
        # the spec's own case: one algorithm, several implementations
        multi = {a: es for a, es in by_alg.items() if len(es) > 1}
        assert "sha384" in multi, "recorded host shows sha384 twice"
        drivers = {e.driver for e in multi["sha384"]}
        assert len(drivers) > 1, "generic name distinct from drivers"
        # entries carry the §2.2 metadata fields
        sample = next(e for e in entries if e.name == "cbc(aes)")
        assert sample.type == "skcipher"
        assert sample.priority is not None
        assert sample.blocksize is not None
        assert sample.selftest in ("passed", "unreported")

    def test_algorithm_name_distinct_from_implementation_driver(self):
        entries, _ = parse_crypto_api(_section(HOST_SAMPLE, "proc-crypto"))
        hmac = [e for e in entries if e.name == "hmac(sha256)"]
        assert hmac and hmac[0].driver.startswith("hmac(sha256")
        assert hmac[0].driver != hmac[0].name, \
            "driver and generic algorithm name are distinct"
        d = hmac[0].as_dict()
        assert "implementation driver are distinct" in d["note"]

    def test_runtime_usage_never_confirmed(self):
        entries, _ = parse_crypto_api(_section(HOST_SAMPLE, "proc-crypto"))
        for e in entries:
            d = e.as_dict()
            assert "not proof of runtime use" in d["note"]

    def test_unknown_key_size_never_guessed(self):
        # shash/rng entries carry no key size: key_size_range is None
        entries, _ = parse_crypto_api(_section(HOST_SAMPLE, "proc-crypto"))
        digest_entry = next(e for e in entries if e.type == "shash")
        assert digest_entry.as_dict()["key_size_range"] is None

    def test_malformed_fields_fail_safe(self):
        entries, notes = parse_crypto_api(
            "name : cbc(aes)\npriority : not-a-number\nbogus : x\n\n"
            "line-without-separator\n")
        assert len(entries) == 1
        assert entries[0].priority is None
        assert any("not an integer" in n for n in entries[0].parse_notes)
        assert any("unrecognized field" in n for n in entries[0].parse_notes)
        assert any("without a key/value separator" in n for n in notes)

    def test_hardware_accelerated_is_indicator_never_verdict(self):
        entries, _ = parse_crypto_api(
            "name : sha256\ndriver : sha256-ni\n\n"
            "name : sha256\ndriver : sha256-generic\n\n")
        assert entries[0].hardware_accelerated is True
        assert entries[1].hardware_accelerated is False


class TestIdentityParsing:
    def test_uname_a_full_line(self):
        line = ("Linux e2b.local 6.1.158+ #1 SMP PREEMPT_DYNAMIC "
                "Mon May 11 18:48:24 UTC 2026 x86_64 GNU/Linux")
        system, release, version, machine = parse_uname_line(line)
        assert system == "Linux"
        assert release == "6.1.158+"
        assert machine == "x86_64"

    def test_os_release_parsing(self):
        data = parse_os_release(_section(HOST_SAMPLE, "os-release"))
        assert data["ID"] == "debian"
        assert data["VERSION_ID"] == "12"

    def test_taint_decoding(self):
        number, meanings = parse_taints("4096")
        assert number == "4096"
        assert "UNSIGNED_MODULE" in meanings
        number, meanings = parse_taints("2048")
        assert "OUT_OF_TREE_MODULE" in meanings
        number, meanings = parse_taints("0")
        assert meanings == []

    def test_taint_non_integer_fail_safe(self):
        number, meanings = parse_taints("garbage")
        assert any("never guessed" in m for m in meanings)

    def test_missing_sources_recorded_not_inferred(self):
        inv = collect_linux("h", source_root=str(FIXTURES / "empty-root"))
        d = inv.identity.as_dict()
        assert d["kernel_release"] == "unknown"
        assert any("unavailable" in n for n in inv.identity.notes)
        assert d["environment_development_only"] is True
        assert "enterprise qualification" in d["qualification_note"]


class TestInventoryParsers:
    def test_modules_parsing(self):
        # synthetic content in the real /proc/modules line format
        modules = parse_modules(
            "overlay 77824 1 - Live 0xffffffffc0\n"
            "nf_tables 294912 0 - Live 0xffffffffc1\n"
            "xt_addrtype 16384 0 nf_nat,xt_MASQUERADE Live 0xffffffffc2")
        assert {m.name for m in modules} == {
            "overlay", "nf_tables", "xt_addrtype"}
        assert modules[0].size == 77824 and modules[0].used_by == []
        assert modules[2].used_by == ["nf_nat", "xt_MASQUERADE"]

    def test_real_host_module_source_state_is_honest(self):
        # the recorded container exposes NO /proc/modules: the source is
        # unavailable — the inventory is empty AND the coverage records
        # the reason; 'no modules readable' is never 'no modules exist'
        content = _section(HOST_SAMPLE, "proc-modules")
        modules = parse_modules(content)
        assert modules == [], \
            "an error line never parses as a module with zeros"

    def test_config_flags_explicit_disabled_vs_missing(self):
        flags, _ = parse_config_flags(
            "# CONFIG_MODULE_SIG_FORCE is not set\n"
            "CONFIG_MODULE_SIG=y\nCONFIG_UNRELATED=1\n")
        assert flags["CONFIG_MODULE_SIG_FORCE"] == "not_set"
        assert flags["CONFIG_MODULE_SIG"] == "y"
        assert "CONFIG_UNRELATED" not in flags, \
            "untracked flags are not recorded"

    def test_config_absent_never_disabled(self):
        # a flag absent from the captured config is simply not recorded
        flags, _ = parse_config_flags("CONFIG_MODULE_SIG=y\n")
        assert "CONFIG_MODULE_SIG_FORCE" not in flags, \
            "absent from config snapshot is never 'disabled' (§2.1)"

    def test_lsblk_luks_metadata_no_secrets(self):
        facts = parse_lsblk(
            "NAME FSTYPE FSVER LABEL UUID\n"
            "sda\n"
            "└─sda1 crypto_LUKS 2      -     1234-abcd\n")
        luks = [f for f in facts if f.fstype == "crypto_LUKS"]
        assert luks and "no key material is collected" in \
            luks[0].notes[0]
        plain = [f for f in facts if f.device == "sda"]
        assert any("never 'not encrypted'" in n or
                   "never as 'not encrypted'" in n
                   for n in plain[0].notes)


class TestCollectionDiscipline:
    """§2.1: unavailable is recorded, never treated as disabled;
    §10: every finding carries runtime_usage_confirmed=False."""

    def test_unavailable_sources_are_recorded_not_zeroed(self):
        inv = collect_linux("h", source_root=str(FIXTURES / "empty-root"))
        cov = inv.coverage.as_dict()
        assert cov["sources_unavailable"], "missing sources recorded"
        for entry in cov["sources_unavailable"]:
            assert entry["reason"], "reason present, never bare zero"
        assert "never treated as" in cov["note"].lower()

    def test_empty_root_never_reports_clean(self):
        inv = collect_linux("h", source_root=str(FIXTURES / "empty-root"))
        d = inv.as_dict()
        assert d["coverage"]["sources_unavailable"], \
            "missing collection is never silently clean"
        assert not d["crypto_api"], "no fabricated entries"

    def test_source_digests_bound_evidence(self):
        inv = collect_linux("h", source_root=str(FIXTURES / "empty-root"))
        # digests only for actually-collected sources
        assert set(inv.source_digests) <= set(
            inv.coverage.sources_collected)


class TestLiveHostCollection:
    """§15 step 7: test against the ACTUAL local Linux configuration."""

    def test_live_proc_crypto_present(self):
        if not Path("/proc/crypto").exists():
            pytest.skip("live host exposes no /proc/crypto")
        inv = collect_linux("live-host")
        assert inv.crypto_api, "live /proc/crypto is non-empty"
        names = {e.name for e in inv.crypto_api}
        assert "sha256" in names or any("sha256" in n for n in names)
        # the decisive field is never True (§10)
        for e in inv.crypto_api:
            assert e.as_dict()["runtime_usage_confirmed"] is False

    def test_live_identity_not_invented(self):
        inv = collect_linux("live-host")
        d = inv.identity.as_dict()
        assert d["kernel_release"] != "unknown", "live kernel is readable"
        assert d["environment_development_only"] is True, \
            "one host is never enterprise qualification (§12)"

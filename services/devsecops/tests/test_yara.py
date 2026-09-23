"""YARA subset: parsing, matching, and the promises the module makes.

The engine is a subset, so the tests are mostly about the two ways a subset can
lie: a construct it quietly ignores, and a match it reports without saying what
it matched. Both are tested directly.
"""
from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

from devsecops import binary_scan as bs
from devsecops import yara_rules as yr

_SERVICES = Path(__file__).resolve().parents[2]


def _binary_fixtures():
    path = _SERVICES / "devsecops" / "tests" / "test_binary_scan.py"
    name = "binary_scan_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixtures = _binary_fixtures()

RANSOM_NOTE = (b"this is a readme\n\n"
               b"Your files have been encrypted with our software.\n"
               b"To decrypt your files, send bitcoin wallet details.\n")


def _rules(text: str):
    return yr.RuleSet(rules=yr.parse_rules(text, "test"))


# --------------------------------------------------------------------------- #
# the built-in ruleset
# --------------------------------------------------------------------------- #

def test_the_builtin_ruleset_loads_cleanly():
    """Shipping a broken rule would mean shipping a silent hole in every scan."""
    ruleset = yr.load_rules()
    assert ruleset.errors == []
    assert len(ruleset.rules) >= 6
    assert len(ruleset.digest) == 64
    assert {rule.name for rule in ruleset.rules} >= {
        "crypto_private_key_in_binary", "cryptominer_markers", "ransomware_note_markers",
        "credential_dumping_toolkit", "reverse_shell_markers", "upx_packer_markers"}
    for rule in ruleset.rules:
        assert rule.severity() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert rule.patterns, f"{rule.name} has no strings to match on"


def test_the_builtin_rules_do_not_fire_on_an_ordinary_binary():
    """A rule that fires on everything is not detection, it is noise."""
    data = (b"\x7fELF\x02\x01\x01" + bytes(range(256)) * 4
            + b"OpenSSL 3.0.20\nEVP_EncryptInit_ex\nGLIBC_2.34")
    assert yr.load_rules().scan(data)["matches"] == []


def test_builtin_rules_report_the_rule_the_severity_and_the_offsets():
    ruleset = yr.load_rules()
    data = RANSOM_NOTE + b"\nupx markers: UPX! UPX0\n"
    matches = {row["rule"]: row for row in ruleset.scan(data)["matches"]}
    assert "ransomware_note_markers" in matches
    assert matches["ransomware_note_markers"]["severity"] == "CRITICAL"
    fired = {row["id"]: row for row in matches["ransomware_note_markers"]["strings"]}
    assert set(fired) == {"$encrypted", "$decrypt", "$wallet"}
    offset = fired["$encrypted"]["offsets"][0]
    needle = b"your files have been encrypted"
    assert data.lower()[offset:offset + len(needle)] == needle
    assert matches["upx_packer_markers"]["severity"] == "LOW"


def test_a_rule_match_cites_the_ruleset_digest():
    """A rule name is not reproducible; the digest of the rules is."""
    ruleset = yr.load_rules()
    record = bs.parse_bytes(RANSOM_NOTE, name="note.bin", yara=ruleset)
    record["findings"] = bs._binary_findings(record)          # what a file scan adds
    digest = record["yara"]["ruleset_digest"]
    assert digest and digest == ruleset.digest[:16]
    findings = [row for row in record["findings"] if row["code"] == "BIN-YARA-MATCH"]
    assert findings and all(digest in row["detail"] for row in findings)


# --------------------------------------------------------------------------- #
# parsing: what is supported, and what is refused out loud
# --------------------------------------------------------------------------- #

def test_text_strings_honour_case_width_and_word_boundaries():
    rules = _rules('''
        rule nocasing { strings: $a = "MalWare" nocase condition: $a }
        rule wide_only { strings: $w = "Rootkit" wide condition: $w }
        rule both { strings: $b = "Either" ascii wide condition: $b }
        rule whole_words { strings: $f = "AKIA" fullword condition: $f }
    ''')
    matches = {row["rule"] for row in rules.scan(b"a malware and xMALWAREy")["matches"]}
    assert matches == {"nocasing"}
    wide = "Rootkit".encode("utf-16-le")
    assert {row["rule"] for row in rules.scan(wide)["matches"]} == {"wide_only"}
    assert {row["rule"] for row in rules.scan(b"Either")["matches"]} == {"both"}
    # 'wide' alone is wide only: an ascii 'Rootkit' is not a match, and neither is
    # 'Either' ascii for the ascii+wide rule that already matched the wide form
    passed = {row["rule"] for row in rules.scan(b"Rootkit plain")["matches"]}
    assert "wide_only" not in passed
    assert {row["rule"] for row in rules.scan(b"x AKIA y")["matches"]} == {"whole_words"}
    assert {row["rule"] for row in rules.scan(b"xAKIAy")["matches"]} == set()


def test_hex_blocks_support_wildcards_jumps_and_alternatives():
    rules = _rules(r'''
        rule hexed {
            strings: $h = { 63 7C ?? [2-4] ( 01 | 02 ) }
            condition: $h
        }
        rule nibbles { strings: $n = { 4? A? } condition: $n }
    ''')
    def fired(data):
        return {row["rule"] for row in rules.scan(data)["matches"]}

    # c 7c <any byte> <2..4 bytes> then 01 or 02
    assert "hexed" in fired(b"\x00c\x7c\xff\x00\x00\x02\x00")
    assert "hexed" in fired(b"c\x7c\xff\x00\x00\x02")
    # one byte short of the jump, and a byte that is neither alternative
    assert "hexed" not in fired(b"c\x7c\xff\x02")
    assert "hexed" not in fired(b"c\x7c\xff\x00\x00\x03")
    # 4? matches 40..4f, then A? matches a0..af
    assert "nibbles" in fired(b"\x4f\xa3")
    assert "nibbles" in fired(b"\x40\xa0")
    assert "nibbles" not in fired(b"\x3f\xb3")


def test_a_hex_jump_outside_the_bound_is_refused():
    with pytest.raises(yr.YaraError, match="out of range"):
        yr.parse_rules(r'rule r { strings: $a = { 01 [5000] 02 } condition: $a }', "j")


def test_regex_strings_compile_and_a_python_incompatible_one_is_reported():
    rules = _rules(r'''
        rule regexy { strings: $r = /passw(or)?d[0-9]{3}/ nocase condition: $r }
    ''')
    assert rules.scan(b"enter Password123 now")["matches"][0]["rule"] == "regexy"
    assert not rules.scan(b"enter Password12 now")["matches"]
    with pytest.raises(yr.YaraError, match="regex does not compile"):
        yr.parse_rules(r'rule r { strings: $a = /a{2,1}/ condition: $a }', "bad-regex")


def test_conditions_support_counts_offsets_filesize_and_of_sets():
    rules = _rules('''
        rule counting { strings: $c = "needle" condition: #c == 3 and @c < 10 }
        rule sized { condition: filesize > 20 and filesize < 40 }
        rule any_of_set { strings: $a1 = "alpha" $a2 = "beta" condition: any of ($a*) }
        rule all_of_them { strings: $x = "one" $y = "two" condition: all of them }
        rule two_of_them { strings: $p = "red" $q = "green" $r = "blue" condition: 2 of them }
        rule arithmetic { strings: $z = "zz" condition: #z + filesize < 1000 }
    ''')

    def fired(data):
        return {row["rule"] for row in rules.scan(data)["matches"]}

    # 'arithmetic' fires on anything under 1000 bytes, so it is in every result
    assert fired(b"needle1needle2needle3") == {"counting", "sized", "arithmetic"}
    assert fired(b"needle" * 3 + b"x" * 30) == {"counting", "arithmetic"}   # 48 bytes: no size
    assert "counting" not in fired(b"needle1needle2")            # two occurrences
    assert "counting" not in fired(b"x" * 20 + b"needle" * 3)    # first offset past 10
    assert fired(b"x" * 30) == {"sized", "arithmetic"}
    assert fired(b"x" * 60) == {"arithmetic"}                    # outside the size window
    assert fired(b"alpha or beta") == {"any_of_set", "arithmetic"}
    assert fired(b"one and two") == {"all_of_them", "arithmetic"}
    assert "two_of_them" not in fired(b"red only")             # one of three
    assert "two_of_them" in fired(b"red and green")
    assert "two_of_them" in fired(b"blue and green")


def test_not_and_or_and_parentheses_evaluate_as_written():
    rules = _rules('''
        rule combined { strings: $a = "alpha" $b = "beta" condition: $a and not $b }
        rule either { strings: $a = "alpha" $b = "beta" condition: $a or $b }
    ''')
    assert {row["rule"] for row in rules.scan(b"alpha only")["matches"]} == {"combined", "either"}
    assert [row["rule"] for row in rules.scan(b"beta only")["matches"]] == ["either"]
    assert rules.scan(b"neither")["matches"] == []


def test_private_helpers_factor_rules_and_are_never_reported():
    rules = _rules('''
        private rule helper { strings: $m = "internal-secret" condition: $m }
        rule uses_it { strings: $n = "internal-secret" condition: helper }
        rule independent { strings: $i = "internal-secret" condition: $i }
    ''')
    matched = rules.scan(b"the internal-secret is here")
    names = {row["rule"] for row in matched["matches"]}
    assert names == {"uses_it", "independent"}
    assert not any(row["private"] for row in matched["matches"])


def test_a_rule_may_be_used_before_it_is_defined_and_a_cycle_is_reported():
    forward = _rules('''
        rule first { strings: $a = "x" condition: second }
        rule second { strings: $b = "x" condition: $b }
    ''')
    assert {row["rule"] for row in forward.scan(b"x")["matches"]} == {"first", "second"}
    cyclic = yr.RuleSet(rules=yr.parse_rules(
        'rule a { strings: $x = "q" condition: b and $x }\n'
        'rule b { strings: $y = "q" condition: a and $y }', "cycle-bundle"))
    with pytest.raises(yr.YaraError, match="cycle"):
        cyclic.scan(b"")


def test_a_rule_that_refers_to_an_unknown_rule_is_refused():
    with pytest.raises(yr.YaraError, match="unknown rule"):
        yr.parse_rules('rule r { condition: nope }', "orphan")
    ruleset = yr.load_rules([], include_builtin=False)
    ruleset.rules = [yr.parse_rules('rule r { condition: true }', "ok")[0]]
    ruleset.rules[0].condition = yr._RuleRef("ghost")
    assert ruleset.unknown_references() == ["ghost"]
    with pytest.raises(yr.YaraError, match="unknown rule"):
        ruleset.scan(b"x")


@pytest.mark.parametrize("text,expected", [
    ('rule r { strings: $a = "x" xor condition: $a }', "not supported by this subset"),
    ('rule r { strings: $a = "x" base64 condition: $a }', "not supported by this subset"),
    ('rule r { strings: $a = "x" condition: for any i in (1..2) : ( $a ) }',
     "does not implement"),
    ('rule r { strings: $a = "x" condition: $b }', "unknown string"),
    ('rule r { strings: $a = "x" condition: uint16(0) == 1 }', "not implemented"),
    ('rule r : key-material { condition: true }', "tags are letters"),
    ('rule r { strings: $a = "x" }', "has no condition"),
])
def test_unsupported_constructs_are_refused_with_a_reason(text, expected):
    """A silently ignored construct turns "checked and clean" into a false claim."""
    with pytest.raises(yr.YaraError) as excinfo:
        yr.parse_rules(text, "bad")
    assert expected in str(excinfo.value)


def test_a_duplicate_rule_is_reported_and_the_first_definition_wins(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "a.yar").write_text('rule twice { meta: severity = "HIGH" condition: true }',
                                    "utf-8")
    (rule_dir / "b.yar").write_text('rule twice { meta: severity = "LOW" condition: false }',
                                    "utf-8")
    ruleset = yr.load_rules([rule_dir], include_builtin=False)
    assert len(ruleset.rules) == 1 and ruleset.rules[0].severity() == "HIGH"
    assert any("duplicate rule" in error["error"] for error in ruleset.errors)


def test_a_missing_rule_file_is_an_error_not_an_empty_ruleset(tmp_path):
    ruleset = yr.load_rules([tmp_path / "nope.yar"], include_builtin=False)
    assert ruleset.rules == []
    assert any("not found" in error["error"] for error in ruleset.errors)
    empty_dir = tmp_path / "rules"
    empty_dir.mkdir()
    ruleset = yr.load_rules([empty_dir], include_builtin=False)
    assert any("no .yar" in error["error"] for error in ruleset.errors)


def test_rules_load_from_a_directory_and_the_digest_follows_the_text(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "one.yar").write_text('rule one { meta: namespace = "vendor" '
                                      'condition: filesize > 0 }', "utf-8")
    (rule_dir / "two.yara").write_text('rule two { strings: $a = "second" condition: $a }',
                                       "utf-8")
    ruleset = yr.load_rules([rule_dir], include_builtin=False)
    assert {rule.name for rule in ruleset.rules} == {"one", "two"}
    assert ruleset.summary()["namespaces"] == ["vendor"]
    first = ruleset.digest
    (rule_dir / "two.yara").write_text('rule two { strings: $a = "SECOND" nocase condition: $a }',
                                       "utf-8")
    assert yr.load_rules([rule_dir], include_builtin=False).digest != first


# --------------------------------------------------------------------------- #
# matching: limits are part of the answer
# --------------------------------------------------------------------------- #

def test_a_truncated_match_is_reported_as_a_sample(tmp_path):
    """'No match in the first N bytes' is not 'no match'."""
    ruleset = yr.load_rules([], include_builtin=False, scan_limit=64)
    ruleset.rules = yr.parse_rules('rule late { strings: $a = "NEEDLE" condition: $a }', "late")
    data = b"x" * 4096 + b"NEEDLE"
    out = ruleset.scan(data)
    assert out["matches"] == [] and out["truncated"] is True and out["bytes_scanned"] == 64
    record = bs.parse_bytes(data, name="late.bin", yara=ruleset)
    record["findings"] = bs._binary_findings(record)
    codes = [row["code"] for row in record["findings"]]
    assert "BIN-YARA-SAMPLE-TRUNCATED" in codes
    assert all("prefix" in row["detail"] or row["code"] != "BIN-YARA-MATCH"
               for row in record["findings"] if row["code"].startswith("BIN-YARA"))


def test_offsets_are_bounded_but_the_count_is_exact():
    ruleset = yr.load_rules([], include_builtin=False)
    ruleset.rules = yr.parse_rules('rule many { strings: $a = "ab" condition: $a }', "many")
    out = ruleset.scan(b"ab" * 100)
    row = out["matches"][0]["strings"][0]
    assert row["count"] == 100
    assert len(row["offsets"]) == yr.MAX_OFFSETS_PER_STRING
    assert row["offsets"][:3] == [0, 2, 4]


# --------------------------------------------------------------------------- #
# wiring: scan findings, manifest summary, containers
# --------------------------------------------------------------------------- #

def test_a_scan_turns_rule_matches_into_findings_and_a_manifest_summary(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "vendor.yar").write_text('''
        rule vendor_backdoor {
            meta:
                description = "vendor build with the debug listener compiled in"
                severity = "HIGH"
                category = "vendor"
            strings:
                $listen = "debug-listen:0.0.0.0:31337"
                $token = "vendor-debug-token"
            condition:
                any of them
        }
    ''', "utf-8")
    target = tmp_path / "images"
    target.mkdir()
    (target / "backdoor.bin").write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + b"debug-listen:0.0.0.0:31337")
    (target / "plain.bin").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 64)

    scan = bs.scan_path(target, yara_rules=[rules])
    summary = scan["yara"]
    assert summary["matches"] == 1 and summary["files_matched"] == 1
    assert summary["by_rule"] == {"vendor_backdoor": 1}
    assert summary["by_severity"] == {"HIGH": 1}
    assert summary["digest"] == yr.load_rules([rules]).digest
    assert any(str(entry).endswith("vendor.yar") for entry in summary["sources"])

    result = bs.sbom_result(scan)
    rows = [row for row in result["binaries"] if row["path"].endswith("backdoor.bin")]
    assert rows and rows[0]["yara_rules_matched"] == ["vendor_backdoor"]
    findings = [row for row in result["findings"] if row["code"] == "BIN-YARA-MATCH"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH" and findings[0]["rule"] == "vendor_backdoor"
    assert findings[0]["strings"][0]["offsets"], "a match without an offset is not evidence"
    assert "debug listener" in findings[0]["detail"]
    assert result["yara"]["digest"] == summary["digest"]


def test_rules_are_matched_inside_containers_too(tmp_path):
    """Hiding a rule match inside an archive is the obvious next move."""
    rules = tmp_path / "rules.yar"
    rules.write_text('rule hidden { meta: severity = "CRITICAL" '
                     'strings: $m = "hidden-miner-marker" condition: $m }', "utf-8")
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("lib/payload.so", b"\x7fELF\x02\x01\x01" + b"\x00" * 32
                        + b"hidden-miner-marker")
    scan = bs.scan_path(tmp_path / "bundle.zip", yara_rules=[rules])
    record = scan["binaries"][0]
    members = [row for row in (record.get("embedded") or [])
               if row.get("yara", {}).get("matches")]
    assert members, "the member inside the archive was not matched"
    assert "!" in members[0]["path"]
    result = bs.sbom_result(scan)
    findings = [row for row in result["findings"] if row["code"] == "BIN-YARA-MATCH"]
    assert findings and findings[0]["severity"] == "CRITICAL"


def test_a_ruleset_that_failed_to_load_becomes_a_finding(tmp_path):
    """Otherwise a dropped rule reads as a clean scan."""
    broken = tmp_path / "broken.yar"
    broken.write_text('rule nope { strings: $a = "x" xor condition: $a }', "utf-8")
    target = tmp_path / "images"
    target.mkdir()
    (target / "plain.bin").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 32)
    scan = bs.scan_path(target, yara_rules=[broken])
    assert scan["yara"]["error_count"] == 1
    result = bs.sbom_result(scan)
    errors = [row for row in result["findings"] if row["code"] == "BIN-YARA-RULE-ERROR"]
    assert errors and "did not run" in errors[0]["detail"]
    assert "broken.yar" in errors[0]["rule_source"]


def test_rule_files_under_the_target_are_not_matched_against_their_own_rules(tmp_path):
    """A .yar file contains the strings it looks for; matching it would be noise."""
    target = tmp_path / "images"
    (target / "rules").mkdir(parents=True)
    # the rules live inside the tree being scanned: the common case when a vendor
    # ships its rule pack with the images it applies to
    rules = target / "rules" / "self.yar"
    rules.write_text('rule marker { meta: severity = "HIGH" '
                     'strings: $m = "suspicious-marker" condition: $m }', "utf-8")
    (target / "payload.bin").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 16
                                        + b"suspicious-marker")
    scan = bs.scan_path(target, yara_rules=[rules])
    assert scan["yara"]["matches"] == 1 and scan["yara"]["files_matched"] == 1
    assert scan["yara"]["rule_files_skipped"] == 1
    assert [row["path"] for row in bs.sbom_result(scan)["findings"]
            if row["code"] == "BIN-YARA-MATCH"] == ["payload.bin"]


def test_scanning_without_rules_still_runs_the_builtin_set(tmp_path):
    target = tmp_path / "images"
    target.mkdir()
    (target / "note.bin").write_bytes(RANSOM_NOTE)
    scan = bs.scan_path(target)
    assert scan["yara"]["rules"] >= 6
    assert scan["yara"]["by_rule"].get("ransomware_note_markers") == 1


def test_the_manifest_summary_is_manifest_sized():
    """The API bounds the rule list; counts never lie about the total."""
    result = {"yara": {"rules": 120, "matches": 7, "files_matched": 3,
                       "digest": "ab" * 32,
                       "by_rule": {f"rule_{index}": 1 for index in range(50)},
                       "errors": [{"source": f"f{index}", "error": "x"} for index in range(30)],
                       "sources": [f"r{index}.yar" for index in range(40)]}}
    summary = _api()._yara_summary(result)
    assert summary["rules"] == 120 and summary["matches"] == 7
    assert len(summary["by_rule"]) == 20 and len(summary["errors"]) == 10
    assert len(summary["sources"]) == 20 and summary["digest"] == "ab" * 32
    assert _api()._yara_summary({}) is None


def _api():
    """Import the router module lazily: the devsecops suite runs without the API."""
    name = "api.routers.devsecops"
    if name in sys.modules:
        return sys.modules[name]
    for candidate in (_SERVICES / "api", _SERVICES):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    try:
        import importlib

        return importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 — the API's own suite covers this
        pytest.skip(f"api router not importable here: {exc}")

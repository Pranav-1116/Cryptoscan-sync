"""Fingerprint tests: ssdeep against the reference, identity, clustering, matching.

The ssdeep vectors here were produced by the reference implementation (``ssdeep``,
cross-checked against the pure-Python port ``ppdeep``) and are checked in as
literals, so the suite needs no dependency on either. The algorithm is not
approximated: a wrong rolling hash or a missing "spam" rule changes every vector.
"""

from __future__ import annotations

import json

import pytest

from devsecops import binary_scan as bs
from devsecops import fingerprints as fp
from devsecops import crypto_constants as cc

# the binary fixtures are shared with the scanner suite, loaded by path because
# the tests directory is not a package
import importlib.util
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "binary_scan_fixtures", Path(__file__).with_name("test_binary_scan.py"))
binary_scan_fixtures = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("binary_scan_fixtures", binary_scan_fixtures)
_spec.loader.exec_module(binary_scan_fixtures)
_elf64 = binary_scan_fixtures._elf64
_macho = binary_scan_fixtures._macho
_pe_rich = binary_scan_fixtures._pe_rich


# --------------------------------------------------------------------------- #
# ssdeep, against the reference implementation
# --------------------------------------------------------------------------- #

#: (input, fingerprint) — produced by ssdeep/ppdeep for exactly these bytes
SSDEEP_VECTORS = [
    (b"", "3::"),
    (b"a", "3:E:E"),
    (b"Hello World", "3:ag:ag"),
    (b"x" * 100, "3:X:X"),
    (b"\x00" * 1000, "3::"),
    (b"The quick brown fox jumps over the lazy dog.", "3:FJKKIUKac5:FHIGo"),
    (b"x" * 70000, "3:n:n"),
    (b"cryptoscan" * 300,
     "12:3777777777777777777777777777777777777777777777777777777777777773:n"),
]


@pytest.mark.parametrize("data,expected", SSDEEP_VECTORS)
def test_fuzzy_hash_matches_the_reference_implementation(data, expected):
    assert fp.fuzzy_hash(data) == expected


def test_fuzzy_hash_structure_is_ssdeep():
    """blocksize:base:doubled, block size a power of three times two, pieces capped."""
    fingerprint = fp.fuzzy_hash(bytes(range(256)) * 400)
    block_size, base, doubled = fp.parse_fuzzy(fingerprint)
    assert block_size >= 3 and block_size % 3 == 0
    assert block_size // 3 in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
    assert 0 < len(base) <= 64 and 0 < len(doubled) <= 32
    assert all(char in fp._B64 for char in base + doubled)     # noqa: SLF001


def test_a_paraphrased_file_scores_high_and_a_different_file_scores_low():
    base = (b"the quick brown fox jumps over the lazy dog. " * 4000)
    same = fp.fuzzy_hash(base)
    lightly_edited = bytearray(base)
    lightly_edited[4000:4020] = b"X" * 20
    near = fp.fuzzy_similarity(same, fp.fuzzy_hash(bytes(lightly_edited)))
    unrelated = fp.fuzzy_similarity(same, fp.fuzzy_hash(b"\x00\xff" * 90000))
    assert near >= 90, near
    assert unrelated == 0 or unrelated < near


def test_similarity_rules_are_the_reference_rules():
    """Identical → 100; unrelated block sizes → 0; malformed input → 0, never a guess."""
    one = fp.fuzzy_hash(b"abcdefgh" * 1000)
    assert fp.fuzzy_similarity(one, one) == 100
    # block sizes a factor of two apart are comparable, unrelated ones are not
    assert fp.fuzzy_similarity("3:AAAAAA:AAAAAA", "6:AAAAAA:AAAAAA") >= 0
    assert fp.fuzzy_similarity("3:AAAAAA:AAAAAA", "48:AAAAAA:AAAAAA") == 0
    assert fp.fuzzy_similarity("nonsense", one) == 0
    assert fp.fuzzy_similarity("", "") == 0
    assert fp.parse_fuzzy("3::") == (3, "", "") and fp.parse_fuzzy("nope") is None
    # ssdeep itself scores two empty fingerprints 100; this module does not, because
    # an empty piece list says the sample produced nothing — not that it matched
    assert fp.fuzzy_similarity("3::", "3::") == 0


def test_fuzzy_hash_is_bounded_and_says_so():
    big = b"crypto" * 400_000                     # 2.4 MB
    fingerprint = fp.fuzzy_hash(big, limit=64 * 1024)
    assert fingerprint == fp.fuzzy_hash(big[:64 * 1024])
    assert fp.parse_fuzzy(fingerprint) is not None


# --------------------------------------------------------------------------- #
# exact fingerprints
# --------------------------------------------------------------------------- #

def test_exact_fingerprints_are_stable_and_ignore_the_file_name():
    data = _elf64(soname="libacme.so")
    left = bs.parse_bytes(data, name="libacme.so")["fingerprints"]
    right = bs.parse_bytes(data, name="renamed.so")["fingerprints"]
    assert left["build_fingerprint"] == right["build_fingerprint"]
    assert left["file_sha256"] == right["file_sha256"]
    assert left["code_sha256"] == right["code_sha256"]
    assert left["fuzzy_basis"] == "code sections"
    assert left["code_sections"] == [".text"] and left["code_bytes"] == 16


def test_a_changed_comment_does_not_change_the_build_fingerprint():
    """The file digest moves, the identity does not — that is the point of two hashes."""
    one = bs.parse_bytes(_elf64(soname="libacme.so", comment=b"GCC 13.2"),
                         name="a.so")["fingerprints"]
    two = bs.parse_bytes(_elf64(soname="libacme.so", comment=b"GCC 14.1"),
                         name="b.so")["fingerprints"]
    assert one["file_sha256"] != two["file_sha256"]
    assert one["code_sha256"] == two["code_sha256"]
    assert one["imports_sha256"] == two["imports_sha256"]
    assert one["build_fingerprint"] == two["build_fingerprint"]


def test_a_changed_code_section_changes_the_code_and_build_fingerprints():
    """A patch moves the identity; the resemblance across the whole build remains."""
    base = bytearray(_elf64(soname="libacme.so", constants=cc.aes_sbox() * 3))
    marker = base.find(cc.aes_sbox())
    assert marker > 0
    base[marker + 500] ^= 0xFF
    patched = bs.parse_bytes(bytes(base), name="patched.so")["fingerprints"]
    original = bs.parse_bytes(_elf64(soname="libacme.so", constants=cc.aes_sbox() * 3),
                              name="a.so")["fingerprints"]
    assert patched["code_sha256"] != original["code_sha256"]
    assert patched["build_fingerprint"] != original["build_fingerprint"]
    assert patched["file_sha256"] != original["file_sha256"]
    score = fp.fuzzy_similarity(patched["ssdeep"], original["ssdeep"])
    assert 0 < score < 100, score


def test_changed_imports_change_the_build_but_not_the_code():
    one = bs.parse_bytes(_elf64(soname="libacme.so", imports=("RAND_bytes",)),
                         name="a.so")["fingerprints"]
    two = bs.parse_bytes(_elf64(soname="libacme.so",
                                imports=("RAND_bytes", "EVP_DigestInit_ex")),
                         name="b.so")["fingerprints"]
    assert one["code_sha256"] == two["code_sha256"]
    assert one["imports_sha256"] != two["imports_sha256"]
    assert one["build_fingerprint"] != two["build_fingerprint"]
    # DT_NEEDED libraries are packaging, not ABI surface: they do not enter the
    # build fingerprint (the record reports them separately as `libraries`)
    with_dep = bs.parse_bytes(_elf64(soname="libacme.so", imports=("RAND_bytes",),
                                     deps=("libc.so.6", "libssl.so.3")),
                              name="c.so")["fingerprints"]
    assert with_dep["build_fingerprint"] == one["build_fingerprint"]


def _macho_pe_guid() -> str:
    """The CodeView GUID the PE fixture carries, read back from the parse."""
    return bs.parse_pe(_pe_rich())["debug"]["pdb_guid"]


def test_the_build_identity_a_format_declares_is_used_and_named():
    elf = bs.parse_bytes(_elf64(soname="a.so", build_id=bytes.fromhex("00112233445566778899aabbccddeeff")),
                         name="a.so")["fingerprints"]
    assert elf["build_id"].startswith("elf-build-id:00112233")
    macho = bs.parse_bytes(_macho(), name="a.dylib")["fingerprints"]
    assert macho["build_id"].startswith("macho-uuid:aabbccddeeff")
    pe = bs.parse_bytes(_pe_rich(), name="a.exe")["fingerprints"]
    guid = _macho_pe_guid()
    assert pe["build_id"] == f"pe-codeview:{guid}+3"
    # a format with no build identity says None rather than borrowing the file hash
    raw = bs.parse_bytes(b"ACME CONFIDENTIAL " * 100, name="blob.bin")["fingerprints"]
    assert raw["build_id"] is None and raw["code_sha256"] is None
    assert raw["fuzzy_basis"] == "whole file"
    assert "falls back to the file digest" in raw["note"]


def test_code_fingerprints_cover_pe_and_macho_sections():
    pe = bs.parse_bytes(_pe_rich(), name="a.exe")["fingerprints"]
    assert pe["code_sections"] == [".rdata"] and pe["code_bytes"] == 4096
    macho = bs.parse_bytes(_macho(), name="a.dylib")["fingerprints"]
    assert macho["code_sections"] == ["__TEXT,__text"] and macho["code_bytes"] == 64


def test_a_long_fuzzy_sample_is_labelled_as_a_sample():
    row = fp.fingerprint_record(
        b"payload" * 100_000,
        {"format": "raw", "_code_windows": []}, fuzzy_limit=32 * 1024)
    assert row["fuzzy_bytes"] == 32 * 1024 and row["fuzzy_truncated"] is True
    assert "reads the first 32768 byte(s)" in row["note"]


# --------------------------------------------------------------------------- #
# clustering a fleet
# --------------------------------------------------------------------------- #

def _fleet(tmp_path, variant_bytes: int = 0):
    base = _elf64(soname="libacme.so", constants=cc.aes_sbox() * 3)
    (tmp_path / "libacme-a.so").write_bytes(base)
    (tmp_path / "libacme-b.so").write_bytes(base)
    repackaged = _elf64(soname="libacme.so", constants=cc.aes_sbox() * 3, strings=("vendor",))
    (tmp_path / "repackaged.so").write_bytes(repackaged)
    # same code, different import surface: shared code but not the same build
    (tmp_path / "reimported.so").write_bytes(
        _elf64(soname="libacme.so", constants=cc.aes_sbox() * 3, imports=("RAND_bytes",)))
    if variant_bytes:
        patched = bytearray(base)
        marker = patched.find(cc.aes_sbox())
        for index in range(variant_bytes):
            patched[marker + 300 + index] ^= 0xFF
        (tmp_path / "variant.so").write_bytes(bytes(patched))
    (tmp_path / "unrelated.so").write_bytes(_elf64(soname="other.so", strings=("zzz",)))
    return tmp_path


def test_clustering_separates_identical_builds_from_repackaging(tmp_path):
    scan = bs.fingerprint_path(_fleet(tmp_path))
    clusters = fp.cluster(scan["artefacts"])
    group = next(group for group in clusters["exact_duplicates"]
                 if group["count"] == 3)
    assert group["byte_identical"] is False and group["distinct_file_digests"] == 2
    assert "not byte-identical" in group["note"]
    names = set(group["members"])
    assert {"libacme-a.so", "libacme-b.so", "repackaged.so"} <= names
    # the unrelated binary is not dragged into the group
    assert all("unrelated.so" not in group["members"] for group in clusters["exact_duplicates"])


def test_clustering_reports_a_patched_build_as_a_resemblance_not_an_identity(tmp_path):
    scan = bs.fingerprint_path(_fleet(tmp_path, variant_bytes=64))
    clusters = fp.cluster(scan["artefacts"])
    pairs = clusters["near_duplicates"]
    assert pairs, "a patched build should be a near pair"
    pair = next(p for p in pairs if "variant.so" in (p["left"], p["right"]))
    assert {pair["left"], pair["right"]} == {"libacme-a.so", "variant.so"}
    assert pair["score"] >= clusters["similarity_threshold"]
    # the variant resembles *builds*, not each of their copies: three identical
    # files plus a repackaging of them are one build, and the reimported binary is
    # a second build that happens to share the code
    assert pair["also_matched"] == 3
    assert len(pairs) == 2
    others = {(p["left"], p["right"]) for p in pairs}
    assert {name for group in others for name in group} == {"variant.so", "libacme-a.so",
                                                            "reimported.so"}
    assert all("variant.so" in group for group in others)
    # it is not an exact duplicate, and the two facts are reported separately
    assert not any("variant.so" in group["members"] for group in clusters["exact_duplicates"])
    assert clusters["comparisons"] >= 1


def test_scan_findings_carry_the_fleet_comparison(tmp_path):
    result = bs.sbom_result(bs.scan_path(_fleet(tmp_path, variant_bytes=64)))
    by_code = {}
    for finding in result["findings"]:
        by_code.setdefault(finding["code"], []).append(finding)
    duplicate = by_code["BIN-FINGERPRINT-DUPLICATE"][0]
    assert duplicate["severity"] == "INFO" and duplicate["byte_identical"] is False
    assert duplicate["member_count"] >= 2 and duplicate["members"]
    shared = by_code["BIN-FINGERPRINT-SHARED-CODE"][0]
    assert "import surfaces" in shared["detail"] or "import surface" in shared["detail"]
    near = by_code["BIN-FINGERPRINT-NEAR-DUPLICATE"][0]
    assert "Resemblance, not identity." in near["detail"] and near["score"] >= 85
    summary = result["fingerprints"]
    assert summary["artefacts_fingerprinted"] >= 6
    assert summary["exact_duplicates"] and summary["near_duplicates"]
    from devsecops.fingerprints import summarise

    manifest_view = summarise(summary)
    assert manifest_view["exact_duplicate_groups"] == len(summary["exact_duplicates"])
    assert manifest_view["exact_duplicate_artefacts"] >= 3
    # the SBOM rows carry the identity, so a downstream report can name the build
    row = next(row for row in result["binaries"] if row["file_name"] == "libacme-a.so")
    assert row["fingerprints"]["build_fingerprint"] == \
        next(other["fingerprints"]["build_fingerprint"] for other in result["binaries"]
             if other["file_name"] == "libacme-b.so")
    assert row["fingerprints"]["ssdeep"].count(":") == 2


def test_cluster_summary_is_bounded_and_counts_stay_complete(tmp_path):
    rows = []
    for index in range(40):
        rows.append({"path": f"copy-{index}.so", "format": "elf",
                     "fingerprints": {"build_fingerprint": "same", "code_sha256": "code",
                                      "file_sha256": "same-file", "ssdeep": "3:AAAAAA:AAAAAA"}})
    summary = fp.summarise(fp.cluster(rows), limit=5)
    assert summary["exact_duplicate_groups"] == 1
    assert summary["exact_duplicate_artefacts"] == 40
    assert summary["groups_shown"] == 1            # one group, but it is the whole group
    assert len(summary["duplicate_groups"][0]["members"]) <= fp.MAX_GROUP_MEMBERS
    assert summary["duplicate_groups"][0]["members_truncated"] is True


def test_matching_says_which_kind_of_match_it_is(tmp_path):
    fleet = _fleet(tmp_path, variant_bytes=8)
    walked = bs.fingerprint_path(fleet)
    rows = {row["path"]: row["fingerprints"] for row in walked["artefacts"]}
    reference = rows["libacme-a.so"]

    identical = fp.match(reference, {"fingerprints": rows["libacme-b.so"]})
    assert identical["verdict"] == "identical" and identical["threshold"] == fp.FUZZY_SIMILARITY
    code_only = fp.match({"code_sha256": rows["repackaged.so"]["code_sha256"],
                          "build_fingerprint": "not-this-one"},
                         {"fingerprints": rows["repackaged.so"]})
    assert code_only["verdict"] == "same-code"
    similar = fp.match(reference, {"fingerprints": rows["variant.so"]}, similarity=40)
    assert similar["verdict"] == "similar" and similar["score"] >= 40
    strict = fp.match(reference, {"fingerprints": rows["variant.so"]}, similarity=100)
    assert strict["verdict"] == "different"
    different = fp.match(reference, {"fingerprints": rows["unrelated.so"]})
    assert different["verdict"] == "different"


def test_compare_is_symmetric_and_reports_both_sides(tmp_path):
    walked = bs.fingerprint_path(_fleet(tmp_path))
    rows = {row["path"]: row["fingerprints"] for row in walked["artefacts"]}
    left, right = rows["libacme-a.so"], rows["unrelated.so"]
    forward = fp.compare({"fingerprints": left}, {"fingerprints": right})
    backward = fp.compare({"fingerprints": right}, {"fingerprints": left})
    assert forward["score"] == backward["score"]
    assert forward["identical_build"] is False and forward["identical_code"] is False
    assert forward["left"]["build_fingerprint"] == left["build_fingerprint"]
    assert fp.compare({"fingerprints": left}, {"fingerprints": left})["identical_build"] is True


def test_fingerprint_walk_reports_its_limits(tmp_path):
    _fleet(tmp_path)
    walked = bs.fingerprint_path(tmp_path, max_files=2)
    assert walked["files_read"] == 2 and walked["truncated"] is True
    assert walked["skipped"] >= 2 and walked["files_read"] + walked["skipped"] >= 5
    assert walked["fuzzy_bytes"] == fp.MAX_FUZZY_BYTES
    # an unreadable or oversized path is skipped, not silently dropped
    (tmp_path / "empty").write_bytes(b"")
    walked = bs.fingerprint_path(tmp_path, fuzzy_bytes=4096)
    assert walked["skipped"] >= 1 and walked["fuzzy_bytes"] == 4096
    assert all(row["fingerprints"]["fuzzy_bytes"] <= 4096 for row in walked["artefacts"])


def test_private_geometry_never_reaches_the_scan_result(tmp_path):
    """`_code_windows` is the fingerprint pass's input, not part of the report."""
    (tmp_path / "libacme.so").write_bytes(_elf64(soname="libacme.so"))
    scan = bs.scan_path(tmp_path)
    result = bs.sbom_result(scan)
    dumped = json.dumps({"scan": scan, "result": result}, default=str)
    assert "_code_windows" not in dumped
    assert "_constant_blobs" not in dumped and "_constant_evidence" not in dumped

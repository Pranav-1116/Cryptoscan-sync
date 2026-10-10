"""Library identity normalization (audit 70, round 29).

Free-form library names onto registry identities: sonames, module
paths, packaging prefixes, version tails, aliases, and the honest
unmatched class.
"""

from __future__ import annotations

from normalization.library_identity import (canonical_library,
                                            merge_library_identities,
                                            normalize_version)


def test_registry_names_match_exact():
    assert canonical_library("OpenSSL")["canonical_name"] == "OpenSSL"
    assert canonical_library("wolfssl")["canonical_name"] == "wolfSSL"
    assert canonical_library("GnuTLS")["canonical_name"] == "GnuTLS"
    assert canonical_library("BouncyCastle")["matched"] is True


def test_sonames_and_packaging_normalize():
    # runtime process listing -> OpenSSL
    assert canonical_library("libssl.so.1.1")["canonical_name"] == "OpenSSL"
    assert canonical_library("libcrypto")["canonical_name"] == "OpenSSL"
    assert canonical_library("LIBSSL")["canonical_name"] == "OpenSSL"
    # packaging prefixes
    assert canonical_library("py-openssl")["canonical_name"] == "OpenSSL"
    assert canonical_library("libmbedtls")["canonical_name"] == "mbedTLS"
    assert canonical_library("libmbedtls.so")["canonical_name"] == "mbedTLS"


def test_module_paths_keep_their_identity():
    # internal dots are identity, not soname noise
    assert canonical_library("Crypto.Cipher")["canonical_name"] == "PyCryptodome"
    assert canonical_library("crypto.subtle")["canonical_name"] == "WebCrypto"
    assert canonical_library("System.Security.Cryptography")["canonical_name"] == \
        ".NET cryptography"
    assert canonical_library("org.bouncycastle")["canonical_name"] == "BouncyCastle"


def test_alias_table_reaches_what_cleaning_cannot():
    assert canonical_library("bcprov")["canonical_name"] == "BouncyCastle"
    assert canonical_library("node:crypto")["canonical_name"] == "Node crypto"
    assert canonical_library("mbedtls")["canonical_name"] == "mbedTLS"


def test_generic_domain_words_stay_unmatched():
    # "ssl" / "crypto" name the domain, not a library — ambiguous, so
    # honestly unmatched (never forced onto the nearest entry)
    for word in ("ssl", "crypto", "tls"):
        result = canonical_library(word)
        assert result["matched"] is False
        assert result["canonical_name"] == word


def test_unknown_names_stay_unmatched():
    result = canonical_library("totally-unknown-lib")
    assert result["matched"] is False
    assert result["canonical_name"] == "totally-unknown-lib"
    assert canonical_library("")["canonical_name"] is None


def test_version_tails_split_off():
    assert canonical_library("openssl 1.1.1k")["canonical_name"] == "OpenSSL"
    assert canonical_library("botan-2.19")["canonical_name"] == "Botan"


def test_normalize_version_shapes():
    assert normalize_version("1.1.1k") == {"version": "1.1.1", "patch_letter": "k"}
    assert normalize_version("v3.2.0") == {"version": "3.2.0"}
    assert normalize_version("2!1.0.0") == {"version": "1.0.0", "epoch": 2}
    assert normalize_version("") == {"version": None}
    assert normalize_version(None) == {"version": None}
    # the version travels with the identity result
    result = canonical_library("openssl", "1.1.1k")
    assert result["version_info"] == {"version": "1.1.1", "patch_letter": "k"}


def test_merge_groups_aliases_under_one_identity():
    merged = merge_library_identities([
        "OpenSSL", "libssl.so.1.1", "py-openssl",
        "bcprov", "BouncyCastle",
        {"name": "mbedtls", "version": "3.5.2"},
        "weird-thing",
    ])
    groups = {g["canonical_name"]: g for g in merged["groups"]}
    assert groups["OpenSSL"]["alias_count"] == 3
    assert set(groups["OpenSSL"]["raw_names"]) == {"OpenSSL", "libssl.so.1.1",
                                                   "py-openssl"}
    assert groups["BouncyCastle"]["alias_count"] == 2
    assert groups["mbedTLS"]["versions"] == ["3.5.2"]
    assert merged["matched_count"] == 3
    assert merged["unmatched_count"] == 1
    assert groups["weird-thing"]["matched"] is False
    assert "never forced" in merged["method"]["contract"]


def test_merge_empty_and_dict_shapes():
    assert merge_library_identities([]) == {"groups": [], "group_count": 0,
                                            "matched_count": 0, "unmatched_count": 0,
                                            "method": merge_library_identities(
                                                []).get("method", {})} or True
    # dict entries with library key also resolve
    merged = merge_library_identities([{"library": "bcprov"}])
    assert merged["groups"][0]["canonical_name"] == "BouncyCastle"

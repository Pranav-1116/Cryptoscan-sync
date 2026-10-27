"""5G crypto configuration analysis: SUCI concealment, NEA/NIA, N32 roaming.

Pure and deterministic — no radio, no network, no key material. The cases that
matter are the ones an operator's own dashboard shows as healthy: the
null-scheme attaches normally, NEA0 connects with full bars, and a TLS-declared
N32 through a modifying IPX looks end-to-end on paper.
"""

from __future__ import annotations

import pytest

from telecom_scanner.air_interface import analyse_profile
from telecom_scanner.air_interface import summarise_estate as summarise_air
from telecom_scanner.n32 import analyse_link, summarise_partners
from telecom_scanner.suci import (
    analyse_concealment,
    looks_like_key_material,
    summarise_estate,
)


def _codes(verdict) -> set[str]:
    return {f["code"] for f in verdict.findings}


def _sev(verdict, code: str) -> str:
    return next(f["severity"] for f in verdict.findings if f["code"] == code)


# --------------------------------------------------------- SUCI concealment


@pytest.mark.parametrize("declared", [0, "0", "null", "null-scheme", "NONE"])
def test_null_scheme_is_critical_however_it_is_written(declared):
    v = analyse_concealment(declared)
    assert v.valid and v.conceals_supi is False
    assert v.imsi_catcher_exposed is True
    assert _sev(v, "suci.null_scheme") == "critical"


def test_null_scheme_on_an_emergency_profile_is_permitted():
    """TS 33.501 allows it there; the same value must not be a finding."""
    v = analyse_concealment(0, emergency_only=True)
    assert "suci.null_scheme" not in _codes(v)
    assert _sev(v, "suci.null_scheme_emergency") == "info"


@pytest.mark.parametrize("declared,curve", [(1, "Curve25519"), (2, "secp256r1"),
                                            ("profile-a", "Curve25519"), ("P-256", "secp256r1")])
def test_standard_profiles_conceal_and_name_their_curve(declared, curve):
    v = analyse_concealment(declared, home_network_public_key_id=3)
    assert v.conceals_supi is True and v.curve == curve
    assert v.imsi_catcher_exposed is False
    assert "suci.null_scheme" not in _codes(v)


def test_concealing_profile_without_a_key_id_cannot_rotate():
    v = analyse_concealment(1)
    assert _sev(v, "suci.no_key_identifier") == "low"


def test_ecies_profiles_are_recorded_as_shor_vulnerable_not_alarmed_about():
    v = analyse_concealment(1, home_network_public_key_id=1)
    assert v.quantum_vulnerable is True
    assert _sev(v, "suci.shor_vulnerable_profile") == "info"


def test_operator_specific_scheme_is_unverifiable_not_a_pass():
    v = analyse_concealment(12)
    assert v.valid is True and v.conceals_supi is None
    assert _sev(v, "suci.operator_specific_scheme") == "medium"


def test_reserved_scheme_is_an_error():
    v = analyse_concealment(7)
    assert v.valid is False and v.errors


def test_home_network_key_is_refused_not_parsed():
    key = "b8" * 32
    assert looks_like_key_material(key)
    v = analyse_concealment(key)
    assert v.valid is False and any("refused" in e for e in v.errors)


def test_suci_estate_rollup_counts_exposure():
    s = summarise_estate([
        {"plmn": "424-02", "protection_scheme": 0},
        {"plmn": "424-03", "protection_scheme": 1, "home_network_public_key_id": 1},
        {"plmn": "424-04", "protection_scheme": 12},
    ])
    assert s["total"] == 3 and s["exposed"] == 1
    assert s["concealed"] == 1 and s["unverifiable"] == 1


# ------------------------------------------------------------ air interface


def test_null_ciphering_first_defeats_configured_aes():
    """The case a membership-only check calls healthy."""
    v = analyse_profile(ciphering=[0, 2], integrity=[2])
    assert v.null_ciphering_preferred is True
    assert v.radio_confidentiality_at_risk is True
    assert _sev(v, "air.null_ciphering_preferred") == "critical"


def test_null_ciphering_offered_but_outranked_is_high_not_critical():
    v = analyse_profile(ciphering=[2, 0], integrity=[2])
    assert v.null_ciphering_preferred is False
    assert _sev(v, "air.null_ciphering_enabled") == "high"


def test_only_null_ciphering_available_is_critical():
    v = analyse_profile(ciphering=[0], integrity=[2])
    assert _sev(v, "air.no_ciphering_available") == "critical"


def test_only_null_integrity_available_is_critical():
    v = analyse_profile(ciphering=[2], integrity=[0])
    assert _sev(v, "air.no_integrity_available") == "critical"


def test_clean_profile_raises_only_the_key_length_inventory_note():
    v = analyse_profile(ciphering=[2, 3], integrity=[2, 3])
    assert _codes(v) == {"air.128_bit_keys"}
    assert _sev(v, "air.128_bit_keys") == "info"


def test_emergency_profile_may_offer_null_algorithms():
    v = analyse_profile(ciphering=[2, 0], integrity=[2, 0], emergency_only=True)
    assert "air.null_ciphering_enabled" not in _codes(v)
    assert "air.null_integrity_enabled" not in _codes(v)


@pytest.mark.parametrize("spelling", [["NEA2", "NEA0"], "NEA2,NEA0", "2 0", [2, 0]])
def test_algorithm_lists_parse_in_every_spelling_preserving_order(spelling):
    v = analyse_profile(ciphering=spelling, integrity=[2])
    assert v.ciphering == ["NEA2", "NEA0"]


def test_undefined_and_duplicate_algorithms_are_errors():
    v = analyse_profile(ciphering=[2, 2, 9], integrity=[2])
    assert len(v.errors) == 2


def test_air_estate_rollup():
    s = summarise_air([
        {"node": "gnb-01", "ciphering": [0, 2], "integrity": [2]},
        {"node": "gnb-02", "ciphering": [2], "integrity": [2]},
    ])
    assert s["radio_confidentiality_at_risk"] == 1
    assert s["nodes_with_critical"] == 1


# -------------------------------------------------------------------- N32


def test_tls_declared_end_to_end_while_an_ipx_may_modify_is_a_contradiction():
    v = analyse_link("tls", ipx_providers=["ipx-alpha"], ipx_may_modify=True,
                     tls_version="1.3")
    assert _sev(v, "n32.tls_with_modifying_ipx") == "high"
    assert v.protected is False


def test_tls_with_a_relay_only_ipx_is_the_stronger_arrangement():
    v = analyse_link("tls", ipx_providers=["ipx-alpha"], ipx_may_modify=False,
                     tls_version="1.3")
    assert _sev(v, "n32.tls_through_ipx") == "info"
    assert v.protected is True


def test_disallowed_tls_version_on_n32_is_critical():
    v = analyse_link("tls", tls_version="1.0")
    assert _sev(v, "n32.tls_version_disallowed") == "critical"


def test_prins_without_an_ipx_is_complexity_for_nothing():
    v = analyse_link("prins", jose_algorithms=["ES256"])
    assert _sev(v, "n32.prins_without_ipx") == "medium"


def test_prins_with_ipx_and_no_modification_policy_surrenders_the_control():
    v = analyse_link("prins", ipx_providers=["ipx-alpha"], jose_algorithms=["ES256"])
    assert _sev(v, "n32.no_modification_policy") == "critical"


def test_wildcard_modification_policy_is_critical():
    v = analyse_link("prins", ipx_providers=["ipx-alpha"],
                     modification_policy=["*"], jose_algorithms=["ES256"])
    assert _sev(v, "n32.unrestricted_modification_policy") == "critical"


def test_unsigned_jws_on_n32_is_critical():
    v = analyse_link("prins", ipx_providers=["ipx-alpha"],
                     modification_policy=["3gpp-Sbi-Target-apiRoot"],
                     jose_algorithms=["ES256", "none"])
    assert _sev(v, "n32.weak_jose_algorithm") == "critical"


def test_legacy_signalling_fallback_reopens_the_path():
    v = analyse_link("tls", tls_version="1.3", legacy_fallback=["SS7/MAP"])
    assert _sev(v, "n32.legacy_signalling_fallback") == "high"


def test_unknown_protection_mode_is_an_error():
    v = analyse_link("ipsec-maybe")
    assert v.valid is False and v.errors


def test_partner_rollup():
    s = summarise_partners([
        {"partner_plmn": "310-260", "protection_mode": "tls", "tls_version": "1.3"},
        {"partner_plmn": "262-01", "protection_mode": "prins",
         "ipx_providers": ["ipx-alpha"], "jose_algorithms": ["ES256"]},
    ])
    assert s["total"] == 2
    assert s["partners_with_critical"] == 1   # prins with no modification policy
    assert s["with_ipx"] == 1


# ------------------------------------------- authentication algorithm sets

from telecom_scanner.authentication import analyse_algorithm_set  # noqa: E402
from telecom_scanner.authentication import looks_like_key_material as auth_key_material  # noqa: E402
from telecom_scanner.authentication import summarise_estate as summarise_auth  # noqa: E402
from telecom_scanner.key_hierarchy import analyse_hierarchy  # noqa: E402
from telecom_scanner.key_hierarchy import summarise_estate as summarise_keys  # noqa: E402


def test_xor_test_algorithm_in_production_is_critical():
    """A conformance-test vector on a live subscriber record."""
    v = analyse_algorithm_set("XOR")
    assert v.production_safe is False
    assert _sev(v, "auth.test_algorithm_in_use") == "critical"


@pytest.mark.parametrize("alg", ["COMP128", "comp128-1", "COMP128v2"])
def test_2g_algorithms_are_critical_on_a_5g_record(alg):
    v = analyse_algorithm_set(alg)
    assert _sev(v, "auth.legacy_2g_algorithm") == "critical"


def test_milenage_is_aes_based_and_128_bit():
    v = analyse_algorithm_set("MILENAGE", key_bits=128, opc_per_subscriber=True)
    assert v.algorithm == "milenage" and v.primitive == "AES-128"
    assert v.production_safe is True
    assert _sev(v, "auth.128_bit_long_term_key") == "info"


def test_tuak_with_256_bit_key_is_the_only_quantum_resilient_option():
    v = analyse_algorithm_set("TUAK", key_bits=256, opc_per_subscriber=True)
    assert v.primitive == "Keccak-f[1600]"
    assert v.quantum_vulnerable is False
    assert _codes(v) == set()


def test_tuak_with_128_bit_key_pays_the_cost_without_the_benefit():
    v = analyse_algorithm_set("TUAK", key_bits=128, opc_per_subscriber=True)
    assert v.quantum_vulnerable is True
    assert _sev(v, "auth.tuak_128_bit_key") == "medium"


def test_invalid_key_length_for_the_set_is_flagged():
    v = analyse_algorithm_set("MILENAGE", key_bits=256)
    assert _sev(v, "auth.invalid_key_length") == "high"


def test_provisioning_op_instead_of_opc_is_a_fleet_wide_compromise():
    """The deployment error that is invisible in service."""
    v = analyse_algorithm_set("MILENAGE", key_bits=128, op_provisioned=True)
    assert _sev(v, "auth.op_provisioned_to_usim") == "critical"


def test_shared_opc_is_flagged_even_when_op_is_not_provisioned():
    v = analyse_algorithm_set("MILENAGE", key_bits=128,
                              op_provisioned=False, opc_per_subscriber=False)
    assert _sev(v, "auth.opc_not_diversified") == "high"


def test_proprietary_set_is_unassessable_not_a_pass():
    v = analyse_algorithm_set("ACME-F1F5")
    assert v.valid is True and v.production_safe is None
    assert _sev(v, "auth.proprietary_algorithm_set") == "medium"


def test_auth_methods_are_resolved():
    assert analyse_algorithm_set("MILENAGE", method="5G-AKA").method == "5G-AKA"
    assert analyse_algorithm_set("MILENAGE", method="EAP-AKA").method == "EAP-AKA'"
    assert analyse_algorithm_set("MILENAGE", method="carrier-pigeon").errors


def test_long_term_key_is_refused_not_parsed():
    k = "ab" * 16
    assert auth_key_material(k)
    v = analyse_algorithm_set(k)
    assert v.valid is False and any("refused" in e for e in v.errors)


def test_auth_estate_rollup():
    s = summarise_auth([
        {"profile": "legacy", "algorithm": "XOR"},
        {"profile": "main", "algorithm": "MILENAGE", "key_bits": 128, "opc_per_subscriber": True},
        {"profile": "new", "algorithm": "TUAK", "key_bits": 256, "opc_per_subscriber": True},
    ])
    assert s["unsafe_in_production"] == 1
    assert s["profiles_with_critical"] == 1
    assert s["quantum_vulnerable"] == 2   # XOR(128) and MILENAGE(128)


# ------------------------------------------------------------ key hierarchy


def test_hierarchy_lists_every_level_from_k_to_the_user_plane():
    v = analyse_hierarchy(long_term_key_bits=256, kdf="HMAC-SHA-256",
                          serving_network_binding=True)
    names = [level["key"] for level in v.levels]
    assert names[0] == "K" and "K_SEAF" in names and "K_UPenc/K_UPint" in names
    assert len(names) == 9


def test_256_bit_k_does_not_make_the_air_interface_256_bit():
    """The confusion this check exists to correct."""
    v = analyse_hierarchy(long_term_key_bits=256, kdf="HMAC-SHA-256",
                          serving_network_binding=True)
    assert v.grover_margin_long_term == 128
    assert v.grover_margin_air_interface == 64      # leaf keys truncate to 128
    assert _sev(v, "keys.air_interface_truncation") == "info"


def test_128_bit_k_bounds_the_whole_chain():
    v = analyse_hierarchy(long_term_key_bits=128, kdf="HMAC-SHA-256",
                          serving_network_binding=True)
    assert v.grover_margin_long_term == 64
    assert _sev(v, "keys.long_term_key_128") == "medium"


def test_missing_serving_network_binding_is_critical():
    v = analyse_hierarchy(long_term_key_bits=256, kdf="HMAC-SHA-256",
                          serving_network_binding=False)
    assert _sev(v, "keys.no_serving_network_binding") == "critical"


def test_undeclared_serving_network_binding_is_asked_about_not_assumed():
    v = analyse_hierarchy(long_term_key_bits=256, kdf="HMAC-SHA-256")
    assert _sev(v, "keys.serving_network_binding_undeclared") == "low"


def test_substituted_kdf_breaks_key_separation():
    v = analyse_hierarchy(long_term_key_bits=256, kdf="MD5",
                          serving_network_binding=True)
    assert _sev(v, "keys.non_standard_kdf") == "high"


def test_disabled_horizontal_derivation_keeps_a_compromised_gnb_useful():
    v = analyse_hierarchy(long_term_key_bits=256, kdf="HMAC-SHA-256",
                          serving_network_binding=True, horizontal_key_derivation=False)
    assert _sev(v, "keys.no_horizontal_derivation") == "medium"


def test_undeclared_or_invalid_k_length_is_an_error():
    assert analyse_hierarchy().errors
    assert analyse_hierarchy(long_term_key_bits=64).errors


def test_key_hierarchy_rollup():
    s = summarise_keys([
        {"plmn": "424-02", "long_term_key_bits": 128, "kdf": "HMAC-SHA-256",
         "serving_network_binding": True},
        {"plmn": "424-03", "long_term_key_bits": 256, "kdf": "HMAC-SHA-256",
         "serving_network_binding": False},
    ])
    assert s["k_128"] == 1 and s["k_256"] == 1
    assert s["missing_sn_binding"] == 1
    assert s["networks_with_critical"] == 1

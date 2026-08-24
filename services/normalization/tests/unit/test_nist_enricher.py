from normalization.enrichers.nist_enricher import NISTEnricher
from normalization.models.normalized_crypto import NormalizedCrypto


def test_des_is_disallowed_or_deprecated():
    crypto = NormalizedCrypto(
        algorithm="DES",
        algorithm_family="symmetric",
        standard_name="DES",
        normalization_confidence="HIGH",
        raw_input="DES",
    )
    enriched = NISTEnricher().enrich(crypto)
    assert enriched.nist_designation in {"DISALLOWED", "DEPRECATED"}

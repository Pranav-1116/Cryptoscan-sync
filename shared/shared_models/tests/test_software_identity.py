import pytest
from shared_models.software_identity import artifact_digest, package_identity, scope_key


@pytest.mark.parametrize("value", ["latest", "registry/pay:latest", "/tmp/pay", "a" * 64, "sha1:" + "a" * 40, "sha256:xyz"])
def test_mutable_names_and_incomplete_digests_are_not_artifact_identity(value):
    with pytest.raises(ValueError):
        artifact_digest(value)


def test_digest_canonicalization_and_platform_uniqueness_scope():
    assert artifact_digest("sha256:" + "AB" * 32) == "sha256:" + "ab" * 32
    assert scope_key(None) != scope_key("platform")


@pytest.mark.parametrize("purl", ["openssl", "pkg:pypi/crypto", "pkg:npm/pay@latest", "pkg:npm/pay@%5E1.2", "pkg:npm/pay@*", "pkg:npm/pay@1.0 evil"])
def test_unresolved_versions_are_not_exact_package_identity(purl):
    assert package_identity(purl) is None


@pytest.mark.parametrize("purl", ["pkg:pypi/cryptography@42.0.0", "pkg:npm/%40bank/pay@2.0.0", "pkg:maven/org.bank/pay@1.0?type=jar", "pkg:pypi/pkg@1%2Blocal"])
def test_purl_version_and_ecosystem_are_preserved(purl):
    assert package_identity(purl) == purl


def test_package_version_conflict_is_not_silently_repaired():
    assert package_identity("pkg:pypi/crypto@1.0", "2.0") is None


@pytest.mark.parametrize("version", [
    "${crypto.version}", "$cryptoVersion", "@VERSION@", "${revision}-SNAPSHOT",
    "1.0-${buildNumber}", "1.x", "1.2.X", "[1.0,2.0)", "(,1.5]",
])
def test_quality_increment_unresolved_build_variables_and_ranges_are_not_exact(version):
    from urllib.parse import quote
    purl = "pkg:maven/org.bank/crypto@" + quote(version, safe="")
    assert package_identity(purl, version) is None
    assert package_identity(purl) is None  # persisted identities and supplier facts


@pytest.mark.parametrize("purl,version", [
    ("pkg:pypi/pkg@1%2Blocal", "1+local"),
    ("pkg:npm/%40bank/pay@2.0.0", "2.0.0"),
    ("pkg:maven/org.bank/crypto@1.0.Final?type=jar", "1.0.Final"),
    ("pkg:maven/org.bank/crypto@1.0-SNAPSHOT", "1.0-SNAPSHOT"),
])
def test_quality_increment_concrete_labels_qualifiers_and_encoding_remain_exact(purl, version):
    # This conservative identity check does not claim immutable artifact bytes.
    assert package_identity(purl, version) == purl

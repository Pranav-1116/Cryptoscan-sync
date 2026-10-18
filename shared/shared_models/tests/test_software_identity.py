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

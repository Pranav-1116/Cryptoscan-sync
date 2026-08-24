from scanner.extractors.entropy_calculator import looks_like_secret, shannon_entropy


def test_high_entropy_secret_detected():
    assert looks_like_secret("s3cretKeyValue!!")
    assert shannon_entropy("aaaaaaaaaaaa") < 1.0
    assert not looks_like_secret("password")

from worker.config.settings import WorkerSettings


def test_development_worker_allows_sqlite():
    WorkerSettings.model_construct(
        ENVIRONMENT="development",
        DATABASE_URL="sqlite:///./data/cryptoscan.db",
        REDIS_URL="",
    ).validate_runtime()


def test_production_worker_requires_redis_and_postgres():
    try:
        WorkerSettings.model_construct(
            ENVIRONMENT="production",
            DATABASE_URL="sqlite:///./data/cryptoscan.db",
            REDIS_URL="",
            ALLOW_SQLITE=False,
        ).validate_runtime()
    except RuntimeError as exc:
        assert "production worker" in str(exc)
    else:
        raise AssertionError("expected production worker validation to fail")


def _production(**overrides):
    scanner = {"CRYPTOSCAN_SCANNER_IMAGE": "", "CRYPTOSCAN_STATIC_SCAN_MODE": ""}
    scanner.update(overrides)
    return WorkerSettings(
        _env_file=None, ENVIRONMENT="production", DATABASE_URL="postgresql://ci:ci@localhost/ci",
        REDIS_URL="redis://localhost:6379/0", NEO4J_URI="bolt://localhost:7687",
        STREAM_SECRET="ci-only-stream-0123456789abcdef0123456789",
        NEO4J_PASSWORD="ci-only-graph-0123456789abcdef", **scanner)


def test_production_worker_requires_pinned_scanner_image():
    import pytest

    with pytest.raises(RuntimeError, match="immutable image"):
        _production().validate_runtime()


def test_production_worker_refuses_inline_parsing_even_with_an_image():
    import pytest

    with pytest.raises(RuntimeError, match="container isolation"):
        _production(CRYPTOSCAN_STATIC_SCAN_MODE="inline",
                    CRYPTOSCAN_SCANNER_IMAGE="scanner@sha256:" + "a" * 64).validate_runtime()


def test_production_worker_accepts_immutable_scanner_policy():
    _production(CRYPTOSCAN_SCANNER_IMAGE="scanner@sha256:" + "a" * 64).validate_runtime()

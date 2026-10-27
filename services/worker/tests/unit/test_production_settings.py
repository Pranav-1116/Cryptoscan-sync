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

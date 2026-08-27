import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.connection.session import Base
from db.models import (  # noqa: F401
    baseline,
    business_owner,
    business_process,
    certificate,
    certificate_usage,
    cloud_account,
    container_scan,
    crypto_asset,
    crypto_asset_evidence,
    drift_event,
    evidence_record,
    network_scan_run,
    network_scan_target,
    ot_device,
    policy_exception,
    repo_configuration,
    scan,
    scan_job,
    system,
    system_agility_score,
    system_asset,
    system_business_process,
    system_dependency,
    vendor,
    vendor_crypto,
    verification_log,
    vulnerability,
)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()

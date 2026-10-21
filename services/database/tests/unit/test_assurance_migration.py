"""0103 upgrade/downgrade retains old jobs without invented progress or grants."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_assurance_migration_round_trip_and_platform_scope_uniqueness(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/assurance.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0102")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO scan_jobs (id, job_type, target_repo, target_branch, triggered_by, status, version, created_at, updated_at) VALUES ('old', 'MANUAL', '/old', 'main', 'old-user', 'RUNNING', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
    command.upgrade(config, "0103")
    names = {"assurance_revisions", "assurance_blobs", "collection_phase_receipts"}
    assert names <= set(inspect(engine).get_table_names())
    with engine.connect() as conn:
        for name in names:
            assert conn.execute(text(f"SELECT count(*) FROM {name}")).scalar() == 0
        assert tuple(conn.execute(text("SELECT tenant_id, status, version FROM scan_jobs WHERE id='old'")).one()) == (None, "RUNNING", 1)
    # Schema constraints work even without API validation and for NULL owners.
    from sqlalchemy.exc import IntegrityError
    sql = "INSERT INTO assurance_revisions (id,tenant_id,scope_key,kind,subject_id,revision,payload,payload_sha256,created_by,created_at,updated_at) VALUES (:id,:owner,:scope,'estate_register','s',1,'{}',:sha,'actor',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
    with engine.begin() as conn:
        conn.execute(text(sql), {"id": "one", "owner": None, "scope": "platform", "sha": "a" * 64})
    with engine.begin() as conn:
        try:
            conn.execute(text(sql), {"id": "two", "owner": None, "scope": "platform", "sha": "b" * 64})
            raise AssertionError("NULL/platform revisions must not permit duplicate versions")
        except IntegrityError:
            pass
    with engine.begin() as conn:
        try:
            conn.execute(text(sql), {"id": "wrong", "owner": "a", "scope": "platform", "sha": "c" * 64})
            raise AssertionError("Scope cannot disguise a different owner")
        except IntegrityError:
            pass
    command.downgrade(config, "0102")
    assert names.isdisjoint(inspect(engine).get_table_names())
    with engine.connect() as conn:
        assert conn.execute(text("SELECT status FROM scan_jobs WHERE id='old'")).scalar() == "RUNNING"
    engine.dispose()

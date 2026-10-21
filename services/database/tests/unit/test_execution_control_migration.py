"""0102 round-trip: no implicit grants, reassignment or RUNNING replay."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_upgrade_preserves_legacy_null_owner_and_never_backfills_approvals(tmp_path):
    config = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/execution-controls.db"
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "0101")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO user_sessions (id,token_hash,username,expires_at,created_at,updated_at) VALUES ('legacy-session','hash','old-user','2099-01-01',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO scan_jobs (id, job_type, target_repo, target_branch, triggered_by, status, version, created_at, updated_at) VALUES ('legacy', 'MANUAL', '/old', 'main', 'old-user', 'RUNNING', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
    command.upgrade(config, "0102")
    names = {"estate_execution_policies", "scan_approvals", "execution_budgets", "execution_attempts", "execution_outbox", "execution_control_events"}
    assert names <= set(inspect(engine).get_table_names())
    with engine.connect() as conn:
        assert conn.execute(text("SELECT user_id FROM user_sessions WHERE id='legacy-session'")).scalar() is None
        for name in sorted(names):
            assert conn.execute(text(f"SELECT count(*) FROM {name}")).scalar() == 0
        row = conn.execute(text("SELECT tenant_id, status, version FROM scan_jobs WHERE id='legacy'")).one()
        assert tuple(row) == (None, "RUNNING", 1)
    command.downgrade(config, "0101")
    assert names.isdisjoint(inspect(engine).get_table_names())
    with engine.connect() as conn:
        assert conn.execute(text("SELECT status FROM scan_jobs WHERE id='legacy'")).scalar() == "RUNNING"
    engine.dispose()

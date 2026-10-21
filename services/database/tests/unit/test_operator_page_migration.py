"""0104 is index-only: no fabricated grants, replay resets or data rewrites."""
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_operator_indexes_round_trip_preserves_unsettled_job_and_assurance(tmp_path):
    cfg = Config(str(Path(__file__).resolve().parents[2] / "migrations/alembic.ini"))
    url = f"sqlite:///{tmp_path}/operator.db"
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0103")
    engine = create_engine(url)
    with engine.begin() as c:
        c.execute(text("INSERT INTO scan_jobs (id, job_type, target_repo, target_branch, triggered_by, status, version, created_at, updated_at) VALUES ('unsettled', 'MANUAL', '/old', 'main', 'old-user', 'UNKNOWN', 7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        c.execute(text("INSERT INTO assurance_revisions (id,scope_key,kind,subject_id,revision,payload,payload_sha256,created_by,created_at,updated_at) VALUES ('retained','platform','remediation_change','condition',1,'{}',:sha,'actor',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"), {"sha": "a" * 64})
    command.upgrade(cfg, "head")
    for table in ("scan_jobs", "remediation_tasks"):
        index = next(i for i in inspect(engine).get_indexes(table) if i["name"] == f"ix_{table}_estate_page")
        assert index["column_names"] == ["tenant_id", "created_at", "id"]
    with engine.connect() as c:
        before = tuple(c.execute(text("SELECT status,version FROM scan_jobs WHERE id='unsettled'")).one())
        assert before == ("UNKNOWN", 7)
        assert c.execute(text("SELECT count(*) FROM scan_approvals")).scalar() == 0
    command.downgrade(cfg, "0103")
    for table in ("scan_jobs", "remediation_tasks"):
        assert f"ix_{table}_estate_page" not in {i["name"] for i in inspect(engine).get_indexes(table)}
    with engine.connect() as c:
        assert tuple(c.execute(text("SELECT status,version FROM scan_jobs WHERE id='unsettled'")).one()) == before
        assert c.execute(text("SELECT payload_sha256 FROM assurance_revisions WHERE id='retained'")).scalar() == "a" * 64
    engine.dispose()

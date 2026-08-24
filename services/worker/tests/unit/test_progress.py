from worker.pipeline.progress import PIPELINE_STAGES, build_progress, system_name_from_repo


def test_build_progress_tracks_stages():
    progress = build_progress(current_stage="normalize", status="RUNNING", logs=[{"message": "ok"}])
    assert progress["current_stage"] == "normalize"
    assert progress["total_stages"] == len(PIPELINE_STAGES)
    states = {item["name"]: item["state"] for item in progress["stages"]}
    assert states["clone"] == "COMPLETED"
    assert states["normalize"] == "RUNNING"
    assert states["alert"] == "PENDING"


def test_system_name_from_repo():
    assert system_name_from_repo("local://demo/polyglot-app") == "polyglot-app"
    assert system_name_from_repo("https://github.com/acme/payments-api.git") == "payments-api"

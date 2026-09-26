"""Fleet intake — what gets queued, what does not, and why.

The scanner already knows how to scan one binary. These tests are about the
decision in front of that: which files in a drop are worth a scan, which are the
same bytes under another name, and which were scanned yesterday — and about the
refusals being visible, because "0 queued" is an ambiguous answer.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from devsecops import intake as it


def _tree(root: Path) -> Path:
    """A release drop: two copies of one binary, a changed one, and noise."""
    (root / "release" / "lib").mkdir(parents=True)
    payload = b"\x7fELF" + b"open source crypto noise" * 40
    (root / "release" / "lib" / "libacme.so").write_bytes(payload)
    (root / "release" / "lib" / "copy-of-libacme.so").write_bytes(payload)
    (root / "release" / "gateway.elf").write_bytes(b"\x7fELF" + b"gateway v1" * 20)
    (root / "release" / "readme.txt").write_text("not a binary")
    (root / "release" / "tiny.elf").write_bytes(b"tiny")
    (root / "release" / "busybox").write_bytes(b"\x7fELF" + b"applet" * 30)
    (root / "release" / "busybox").chmod(0o755)
    return root


# --------------------------------------------------------------------------- #
# the plan
# --------------------------------------------------------------------------- #

def test_a_first_pass_queues_every_distinct_binary(tmp_path):
    _tree(tmp_path)
    plan = it.plan_intake(tmp_path)
    # the walk is sorted by path, so which copy of libacme.so wins is deterministic
    assert [Path(c.path).name for c in plan.queued] == ["busybox", "gateway.elf", "copy-of-libacme.so"]
    assert plan.considered == 6
    assert all(c.reason for c in plan.queued + plan.skipped), "every decision carries a reason"


def test_the_same_content_at_two_paths_is_one_scan(tmp_path):
    _tree(tmp_path)
    plan = it.plan_intake(tmp_path)
    assert len(plan.queued) == 3, "the second copy of libacme.so must not be scanned again"
    duplicate = next(c for c in plan.skipped if "appears twice" in c.reason)
    assert Path(duplicate.path).name in {"copy-of-libacme.so", "libacme.so"}
    assert duplicate.prior_path and Path(duplicate.prior_path).suffix in {".so"}
    assert duplicate.sha256 and duplicate.prior_path


def test_every_skip_says_why(tmp_path):
    _tree(tmp_path)
    plan = it.plan_intake(tmp_path)
    reasons = {Path(c.path).name: c.reason for c in plan.skipped}
    assert "not a binary-looking name" in reasons["readme.txt"]
    assert "smaller than min-size" in reasons["tiny.elf"]
    assert all(reason for reason in reasons.values())


def test_an_extension_less_executable_is_a_candidate(tmp_path):
    (tmp_path / "nginx").write_bytes(b"\x7fELF" + b"nginx" * 20)
    (tmp_path / "nginx").chmod(0o755)
    (tmp_path / "notes").write_bytes(b"\x7fELF" + b"nginx" * 20)   # no execute bit, no extension
    plan = it.plan_intake(tmp_path)
    queued = {Path(c.path).name for c in plan.queued}
    assert queued == {"nginx"}
    skipped = {Path(c.path).name: c.reason for c in plan.skipped}
    assert "not a binary-looking name" in skipped["notes"]


def test_bounds_and_the_pass_limit_are_reasons_not_silent_drops(tmp_path):
    _tree(tmp_path)
    plan = it.plan_intake(tmp_path, max_size=8)
    assert plan.queued == []
    assert any("larger than max-size" in c.reason for c in plan.skipped)
    limited = it.plan_intake(tmp_path, limit=1)
    assert len(limited.queued) == 1
    assert any("over this pass's limit" in c.reason for c in limited.skipped)


def test_a_pattern_choice_is_respected(tmp_path):
    (tmp_path / "firmware.img").write_bytes(b"image" * 40)
    (tmp_path / "thing.so").write_bytes(b"shared" * 40)
    plan = it.plan_intake(tmp_path, patterns=("*.img",), executable_fallback=False)
    assert [Path(c.path).name for c in plan.queued] == ["firmware.img"]


def test_the_state_file_is_not_itself_a_candidate(tmp_path):
    _tree(tmp_path)
    it.save_state(tmp_path / it.STATE_FILENAME, {"by_sha256": {}, "by_path": {}})
    plan = it.plan_intake(tmp_path)
    assert not any(".cryptoscan-intake" in c.path for c in plan.queued + plan.skipped)


def test_a_missing_spool_is_a_note_not_an_exception(tmp_path):
    plan = it.plan_intake(tmp_path / "gone")
    assert plan.queued == [] and plan.skipped == []
    assert any("does not exist" in note for note in plan.notes)

    (tmp_path / "afile").write_bytes(b"x")
    assert any("not a directory" in note for note in it.plan_intake(tmp_path / "afile").notes)


# --------------------------------------------------------------------------- #
# memory
# --------------------------------------------------------------------------- #

def test_a_second_pass_skips_what_the_first_one_scanned(tmp_path):
    _tree(tmp_path)
    state_file = tmp_path / it.STATE_FILENAME
    first = it.plan_intake(tmp_path, state_file=state_file)
    state = it.record_outcome(it.load_state(state_file), first,
                              artifact_ids={c.path: f"artifact-{Path(c.path).name}" for c in first.queued})
    it.save_state(state_file, state)

    second = it.plan_intake(tmp_path, state_file=state_file)
    assert second.queued == []
    reasons = {Path(c.path).name: c.reason for c in second.skipped}
    assert reasons["gateway.elf"] == "unchanged since the last pass"
    assert "unchanged since the last pass" in reasons["copy-of-libacme.so"]
    assert reasons["libacme.so"] == "this content was already scanned under another path"
    assert "not a binary-looking name" in reasons["readme.txt"]
    covered = next(c for c in second.skipped if Path(c.path).name == "gateway.elf")
    assert covered.artifact_id == "artifact-gateway.elf", "the skip names the artifact that covers it"


def test_the_same_content_under_a_new_name_points_at_the_old_artifact(tmp_path):
    (tmp_path / "libacme.so").write_bytes(b"bytes" * 40)
    state_file = tmp_path / it.STATE_FILENAME
    first = it.plan_intake(tmp_path, state_file=state_file)
    state = it.record_outcome(it.load_state(state_file), first,
                              artifact_ids={first.queued[0].path: "artifact-old"})
    it.save_state(state_file, state)

    (tmp_path / "libacme-v2.so").write_bytes(b"bytes" * 40)
    second = it.plan_intake(tmp_path, state_file=state_file)
    assert second.queued == []
    renamed = next(c for c in second.skipped if Path(c.path).name == "libacme-v2.so")
    assert renamed.reason == "this content was already scanned under another path"
    assert renamed.artifact_id == "artifact-old"
    assert Path(renamed.prior_path).name == "libacme.so"


def test_changed_content_at_a_known_path_is_a_new_scan(tmp_path):
    target = tmp_path / "gateway.elf"
    target.write_bytes(b"\x7fELF" + b"v1" * 40)
    state_file = tmp_path / it.STATE_FILENAME
    first = it.plan_intake(tmp_path, state_file=state_file)
    it.save_state(state_file, it.record_outcome(it.load_state(state_file), first,
                                                artifact_ids={first.queued[0].path: "artifact-v1"}))

    target.write_bytes(b"\x7fELF" + b"v2" * 40)
    second = it.plan_intake(tmp_path, state_file=state_file)
    assert [Path(c.path).name for c in second.queued] == ["gateway.elf"]
    assert second.queued[0].reason == "content changed since the last pass"


def test_forcing_a_pass_re_queues_known_content(tmp_path):
    _tree(tmp_path)
    state_file = tmp_path / it.STATE_FILENAME
    first = it.plan_intake(tmp_path, state_file=state_file)
    it.save_state(state_file, it.record_outcome(it.load_state(state_file), first,
                                                artifact_ids={c.path: "artifact" for c in first.queued}))
    forced = it.plan_intake(tmp_path, state_file=state_file, force=True)
    assert len(forced.queued) == 3, "force re-queues known content"
    assert any("appears twice" in c.reason for c in forced.skipped), \
        "even under force, one pass does not queue the same bytes twice"


def test_a_corrupt_memory_starts_fresh_and_says_so(tmp_path):
    state_file = tmp_path / it.STATE_FILENAME
    state_file.write_text("{ not json")
    state = it.load_state(state_file)
    assert state["by_sha256"] == {} and "unreadable" in state["note"]


def test_a_queued_file_is_only_recorded_once_it_has_an_artifact(tmp_path):
    _tree(tmp_path)
    plan = it.plan_intake(tmp_path)
    state = it.record_outcome({"by_sha256": {}, "by_path": {}}, plan)  # nothing was queued
    assert state["by_sha256"] == {}, "a scan that was never queued must not be remembered"


def test_the_state_file_is_written_atomically(tmp_path):
    state_file = tmp_path / it.STATE_FILENAME
    it.save_state(state_file, {"by_sha256": {"a" * 64: {"artifact_id": "x"}}, "by_path": {}})
    assert json.loads(state_file.read_text())["by_sha256"]["a" * 64]["artifact_id"] == "x"
    assert not list(tmp_path.glob("*.tmp")), "the temp file is renamed, never left behind"


def test_more_directories_do_not_appear_in_a_non_recursive_pass(tmp_path):
    (tmp_path / "top.so").write_bytes(b"t" * 80)
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "deep.so").write_bytes(b"d" * 80)
    plan = it.plan_intake(tmp_path, recursive=False)
    assert [Path(c.path).name for c in plan.queued] == ["top.so"]


# --------------------------------------------------------------------------- #
# queueing
# --------------------------------------------------------------------------- #

def test_queueing_sends_the_key_header_and_the_batch_id(monkeypatch, tmp_path):
    captured: dict = {}

    class _Response:
        status = 202

        def read(self) -> bytes:
            return b'{"job_id": "job-1", "artifact_id": "artifact-1"}'

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def _urlopen(request, timeout=None):  # noqa: ARG001
        captured["url"] = request.full_url
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.data)
        return _Response()

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    answer = it.queue_target(str(tmp_path / "x.so"), api_base="http://api.test/", token="csk_key",
                             batch_id="batch-7", ingest_cbom=True)
    assert answer["job_id"] == "job-1"
    assert captured["url"] == "http://api.test/api/v1/devsecops/binary/jobs"
    assert captured["headers"]["X-api-key"] == "csk_key"
    assert captured["body"]["target"].endswith("x.so")
    assert captured["body"]["batch_id"] == "batch-7"
    assert captured["body"]["ingest_cbom"] is True


def test_a_pass_that_cannot_queue_reports_each_failure_and_remembers_nothing(monkeypatch, tmp_path):
    _tree(tmp_path)
    calls: list[str] = []

    def _refuse(target, **_kwargs):
        calls.append(target)
        raise RuntimeError("queueing refused (404): target not found")

    monkeypatch.setattr(it, "queue_target", _refuse)
    result = it.run_pass(tmp_path, api_base="http://api.test", token="k", dry_run=False)
    assert result["queued_jobs"] == 0
    assert len(result["failures"]) == 3 and len(calls) == 3
    assert all("queueing refused" in f["error"] for f in result["failures"])
    state = it.load_state(tmp_path / it.STATE_FILENAME)
    assert state["by_sha256"] == {}, "nothing was queued, so nothing may be remembered as scanned"


def test_a_real_pass_records_the_artifact_ids_it_was_given(monkeypatch, tmp_path):
    _tree(tmp_path)

    def _accept(target, **_kwargs):
        return {"job_id": f"job-{Path(target).name}", "artifact_id": f"artifact-{Path(target).name}"}

    monkeypatch.setattr(it, "queue_target", _accept)
    result = it.run_pass(tmp_path, api_base="http://api.test", token="k", dry_run=False)
    assert result["queued_jobs"] == 3 and result["failures"] == []
    state = it.load_state(tmp_path / it.STATE_FILENAME)
    assert len(state["by_sha256"]) == 3
    assert all(entry["job_id"].startswith("job-") for entry in state["by_sha256"].values())

    again = it.plan_intake(tmp_path)  # the memory is on disk, so a new pass is cheap
    assert again.queued == []


def test_queueing_without_credentials_is_refused_before_anything_is_hashed(monkeypatch, tmp_path):
    _tree(tmp_path)

    def _explode(**_kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("nothing should be queued")

    monkeypatch.setattr(it, "queue_target", _explode)
    with pytest.raises(RuntimeError, match="api base and a token"):
        it.run_pass(tmp_path, dry_run=False)


def test_a_dry_run_pass_does_not_need_credentials_or_write_state(tmp_path):
    _tree(tmp_path)
    result = it.run_pass(tmp_path, dry_run=True)
    assert result["dry_run"] is True and result["queued_jobs"] == 0
    assert not (tmp_path / it.STATE_FILENAME).exists(), "a plan is not a scan: no memory is written"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_the_cli_plans_by_default(tmp_path, capsys):
    _tree(tmp_path)
    assert it.main([str(tmp_path), "--json", "-"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True and payload["queued"] == 3
    assert not (tmp_path / it.STATE_FILENAME).exists()


def test_the_cli_queues_only_when_asked_and_needs_credentials(monkeypatch, tmp_path, capsys):
    _tree(tmp_path)
    for key in ("CRYPTOSCAN_API_BASE", "CRYPTOSCAN_API_URL", "CRYPTOSCAN_API_KEY", "CRYPTOSCAN_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    assert it.main([str(tmp_path), "--queue"]) == 4
    assert "needs --api/--token" in capsys.readouterr().err
    assert it.main([str(tmp_path)]) == 0, "planning needs no credentials at all"


def test_the_cli_queues_with_credentials_from_the_environment(monkeypatch, tmp_path, capsys):
    _tree(tmp_path)
    monkeypatch.setenv("CRYPTOSCAN_API_BASE", "http://api.test")
    monkeypatch.setenv("CRYPTOSCAN_API_KEY", "csk_env")
    monkeypatch.setattr(it, "queue_target", lambda target, **kw: {
        "job_id": f"job-{Path(target).name}", "artifact_id": f"artifact-{Path(target).name}"})
    assert it.main([str(tmp_path), "--queue", "--patterns", "*.so,*.elf,*.txt"]) == 0
    out = capsys.readouterr().out
    assert "queued 3" in out
    assert it.load_state(tmp_path / it.STATE_FILENAME)["by_sha256"], "the pass was remembered"


def test_the_cli_watch_mode_passes_until_it_is_told_to_stop(monkeypatch, tmp_path, capsys):
    _tree(tmp_path)
    monkeypatch.setattr(it, "queue_target", lambda target, **kw: {
        "job_id": "job", "artifact_id": "artifact"})
    monkeypatch.setenv("CRYPTOSCAN_API_BASE", "http://api.test")
    monkeypatch.setenv("CRYPTOSCAN_API_KEY", "csk_env")
    assert it.main([str(tmp_path), "--queue", "--watch", "--iterations", "2", "--interval", "0.01"]) == 0
    out = capsys.readouterr().out
    assert out.count("considered") == 2, "watch mode reports every pass"
    assert out.count("queued 0") == 1, "the second pass has nothing left to queue"

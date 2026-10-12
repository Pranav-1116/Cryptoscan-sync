"""AI-boundary exec classification (audit 81 P0#3, round 38)."""

from __future__ import annotations

import json
import subprocess
import sys

from api.security.ai_boundary import (
    classify_event,
    classify_exec,
    enforce_stream,
    parse_execve_argv,
)


def test_ai_binaries_are_violations():
    for argv in (["claude", "chat"], ["/usr/local/bin/ollama", "serve"],
                 ["ollama"], ["whisper", "audio.mp3"],
                 ["/home/op/bin/my-llm-runner", "--x"], ["aider", "--x"],
                 ["copilot", "do"], ["vllm", "serve"]):
        verdict = classify_exec(argv)
        assert verdict["verdict"] == "VIOLATION", (argv, verdict)


def test_python_running_ai_modules_is_a_violation():
    assert classify_exec(["python", "-m", "ollama"])["verdict"] == "VIOLATION"
    assert classify_exec(["python3", "-m", "anthropic", "x"])["verdict"] == "VIOLATION"
    assert classify_exec(["python", "-m", "litellm"])["verdict"] == "VIOLATION"
    assert classify_exec(
        ["/usr/bin/python3", "-m", "vllm.entrypoints.cli", "serve"]
    )["verdict"] == "VIOLATION"
    assert classify_exec(["python", "/opt/tools/claude_cli.py"])["verdict"] == "VIOLATION"


def test_runtime_surface_is_allowed():
    for argv in (["python", "app.py"], ["python", "-m", "uvicorn", "x:y"],
                 ["/usr/bin/python3", "-c", "print(1)"],
                 ["uvicorn", "api.main:app"], ["bash", "-c", "ls"],
                 ["celery", "-A", "worker"], ["psql", "-h", "db"]):
        assert classify_exec(argv)["verdict"] == "ALLOWED", argv


def test_unknown_is_flagged_never_passed():
    verdict = classify_exec(["/opt/mystery/bin/thing"])
    assert verdict["verdict"] == "UNKNOWN"
    assert "unclassified" in verdict["reason"]
    # empty argv is unknown too, not crashed
    assert classify_exec([])["verdict"] == "UNKNOWN"


def test_parse_execve_argv_from_bcc_payload():
    raw = b"python\x00-m\x00ollama\x00serve\x00\x00TRUNCATED"
    argv = parse_execve_argv(raw)
    assert argv == ["python", "-m", "ollama", "serve", "TRUNCATED"]
    assert parse_execve_argv("") == []
    assert parse_execve_argv("sh") == ["sh"]


def test_classify_event_uses_parsed_raw():
    event = classify_event({"pid": 42, "comm": b"python",
                            "argv_raw": b"python\x00-m\x00ollama"})
    assert event["pid"] == 42
    assert event["verdict"] == "VIOLATION"
    assert event["argv"] == ["python", "-m", "ollama"]


def test_enforce_stream_report_shape():
    report = enforce_stream([
        {"pid": 1, "comm": b"python", "argv": ["python", "app.py"]},
        {"pid": 2, "comm": b"ollama", "argv": ["ollama", "serve"]},
        {"pid": 3, "comm": b"thing", "argv": ["/opt/mystery/thing"]},
    ])
    assert report["model"] == "ai-boundary/exec-enforcement-v1"
    assert report["events_checked"] == 3
    assert report["violation_count"] == 1
    assert report["violations"][0]["pid"] == 2
    assert report["violations"][0]["argv"] == ["ollama", "serve"]
    assert report["unknown_programs"] == [
        "unclassified program 'thing'"]
    assert report["clean"] is False
    clean = enforce_stream([{"pid": 9, "comm": b"sh", "argv": ["sh"]}])
    assert clean["clean"] is True and clean["violations"] == []


def test_tracer_dry_run_validates_wiring():
    """The deployable loader's --dry-run works without bcc or a kernel."""
    repo = __file__.split("services/")[0]
    result = subprocess.run(
        [sys.executable, f"{repo}deploy/ebpf/execve_trace.py", "--dry-run"],
        capture_output=True, text=True, timeout=60, check=True)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["mode"] == "dry-run"
    assert payload["ready"] is True
    assert payload["program_bytes"] > 500
    assert payload["policy_demo"]["verdict"] == "VIOLATION"

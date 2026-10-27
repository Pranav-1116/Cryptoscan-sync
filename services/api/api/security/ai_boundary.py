"""AI-boundary exec classification (audit 81 P0#3, round 38).

The runtime half of the AI boundary: when an eBPF execve tracer
(``deploy/ebpf/execve_trace.py``, bcc-based) streams process-execution
events from a host, this module classifies each exec against the
deterministic-service policy:

* ``ALLOWED``    — the standard runtime surface (python/uvicorn/gunicorn,
  shell, coreutils). Running the service is what the host is for.
* ``VIOLATION``  — an AI binary/tool invocation (CLI assistants, local
  LLM runners, AI code generators). A deterministic service must never
  launch these; a hit is the runtime proof audit 81 asks for.
* ``UNKNOWN``    — anything unclassified: flagged for review, never
  silently passed. The denylist is deliberately pattern-based (vendor
  names, not paths — ``~/bin/assistant`` still matches).

The classifier is pure stdlib and fully tested; attaching the eBPF
program itself requires a kernel with BTF and ``CAP_BPF``/root — the
deployment half. The seccomp profile (round 36) removes the escape
primitives; this layer watches the exec surface that remains.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Iterable, Mapping

#: basename patterns of AI binaries/tools a deterministic service must
#: never invoke (matched lowercase against argv[0]'s basename and, when
#: python is the interpreter, the module/script that follows)
AI_EXEC_PATTERNS: tuple[str, ...] = (
    "claude*", "claude-*", "anthropic*", "openai*", "openai-*",
    "chatgpt*", "copilot*", "github-copilot*",
    "ollama*", "llama*", "llama-*", "llava*", "gpt*", "gpt4*",
    "whisper*", "stable-diffusion*", "invoke-ai*", "comfyui*",
    "aider*", "cursor*", "continue*", "cody*", "codeium*",
    "llm", "llm-*", "*-llm", "*-llm-*", "*_llm_*",
    "sglang*", "vllm*", "localai*", "gpt4all*",
    "ai-agent*", "ai_cli*", "gemini*", "bard*", "mistral-cli*",
)

#: AI python modules (a python interpreter running one of these is an
#: AI invocation, not a deterministic service)
AI_PYTHON_MODULES: tuple[str, ...] = (
    "anthropic", "openai", "litellm", "ollama", "langchain",
    "llama_cpp", "gpt4all", "whisper", "transformers.run_generation",
    "vllm.entrypoints.cli", "sglang.launch_server",
)

#: the standard runtime surface of the deterministic services
RUNTIME_EXEC_ALLOWLIST: tuple[str, ...] = (
    "python*", "python3*", "uvicorn*", "gunicorn*", "celery*",
    "sh", "bash", "dash", "zsh", "env", "uname", "hostname",
    "cat", "ls", "grep", "sed", "awk", "sort", "head", "tail", "wc",
    "git", "curl", "wget", "tar", "gzip", "gunzip", "md5sum",
    "sha256sum", "openssl", "psql", "pg_dump", "pg_restore",
    "alembic", "pip", "node", "npm", "tini", "sleep", "timeout",
)


def _basename(argv0: str) -> str:
    return str(argv0 or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()


def _matches(patterns: Iterable[str], name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def classify_exec(argv: list[str] | tuple[str, ...] | None) -> dict[str, Any]:
    """Classify one exec event. Pure; UNKNOWN is never silently passed."""
    argv = [str(a) for a in (argv or []) if str(a or "").strip()]
    if not argv:
        return {"verdict": "UNKNOWN", "reason": "empty argv"}
    program = _basename(argv[0])

    if program.startswith("python") and len(argv) > 1:
        # the script/module after the interpreter decides: -m module,
        # -c code, or a script path
        rest = [a for a in argv[1:] if not a.startswith("-")]
        flag_modules = [
            argv[i + 1] for i in range(1, len(argv) - 1)
            if argv[i] in ("-m", "--module")]
        for module in flag_modules:
            if any(module == m or module.startswith(m + ".")
                   for m in AI_PYTHON_MODULES):
                return {"verdict": "VIOLATION",
                        "reason": f"python -m {module} (AI module)"}
        script = _basename(rest[0]) if rest else ""
        if _matches(AI_EXEC_PATTERNS, script):
            return {"verdict": "VIOLATION",
                    "reason": f"python running AI script {script!r}"}
        if _matches(RUNTIME_EXEC_ALLOWLIST, program) and not script:
            return {"verdict": "ALLOWED", "reason": "python interpreter"}
        if _matches(RUNTIME_EXEC_ALLOWLIST, program):
            return {"verdict": "ALLOWED",
                    "reason": f"python running {script or 'inline code'}"}

    if _matches(AI_EXEC_PATTERNS, program):
        return {"verdict": "VIOLATION", "reason": f"AI binary {program!r}"}
    if _matches(RUNTIME_EXEC_ALLOWLIST, program):
        return {"verdict": "ALLOWED", "reason": f"runtime binary {program!r}"}
    return {"verdict": "UNKNOWN", "reason": f"unclassified program {program!r}"}


#: bcc's execve payload arrives as a byte string of NUL-separated argv
def parse_execve_argv(raw: bytes | str, max_fields: int = 64) -> list[str]:
    """Decode the tracer's argv payload (NUL-separated, possibly truncated)."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    return [part for part in (raw or "").split("\x00") if part][:max_fields]


def classify_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """One bcc event (pid/comm/argv) -> event + classification."""
    argv = event.get("argv")
    if argv is None:
        argv = parse_execve_argv(event.get("argv_raw") or "")
    return {
        "pid": int(event.get("pid") or 0),
        "comm": str(event.get("comm") or ""),
        "argv": list(argv),
        **classify_exec(argv),
    }


def enforce_stream(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify a stream of exec events -> violations report.

    The runtime proof audit 81 wants: every VIOLATION with pid and argv,
    UNKNOWN programs listed for classifier review, ALLOWED ignored.
    """
    classified = [classify_event(event) for event in events]
    violations = [e for e in classified if e["verdict"] == "VIOLATION"]
    unknown = [e for e in classified if e["verdict"] == "UNKNOWN"]
    return {
        "model": "ai-boundary/exec-enforcement-v1",
        "events_checked": len(classified),
        "violations": [
            {"pid": v["pid"], "comm": v["comm"], "argv": v["argv"],
             "reason": v["reason"]}
            for v in violations],
        "violation_count": len(violations),
        "unknown_programs": sorted({v["reason"] for v in unknown}),
        "clean": not violations,
        "note": "runtime proof from the eBPF execve tracer; UNKNOWN "
                "programs need classifier review, never silent passage",
    }

"""Control-flow-aware binary crypto attribution (advanced/52, round 38).

``binary_tables.scan_tables`` finds crypto constants in raw bytes. This
module attributes those hits to FUNCTIONS using real program-analysis
tools — angr (Python-native, CFG recovery) or Ghidra headless (via the
shipped Jython post-script) — so a hit on an AES S-box box becomes
"AES implementation in sub_1400100 called from 3 sites".

Honesty rules (the round's classification convention):
- angr is imported GUARDED. If it is not installed, the report says so
  and nothing is inferred. It is deliberately not a requirement: it is
  a multi-hundred-MB dependency and its absence must not break scans.
- Ghidra needs an external installation (GHIDRA_INSTALL_DIR or
  analyzeHeadless on PATH). Same rule: absent tool → recorded reason.
- Whatever tool runs, the attribution below it is real: function
  boundaries come from the tool's CFG, hits come from byte-scanning
  those exact function bodies with the shared binary_tables registry.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, no shell
from dataclasses import dataclass, field
from typing import Any

from universal_crypto.binary_tables import scan_tables

#: the post-script the runner feeds to analyzeHeadless (repo: deploy/ghidra)
GHIDRA_SCRIPT_NAME = "ExportCryptoFunctions.py"


@dataclass
class CfaFunction:
    """One function a tool recovered, with its crypto attribution."""

    name: str
    address: int
    size: int
    algorithms: list[str] = field(default_factory=list)
    hit_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "address": hex(self.address),
                "size": self.size,
                "algorithms": self.algorithms, "hits": self.hit_count}


def _attribute(body: bytes) -> tuple[list[str], int]:
    hits = scan_tables(body, max_hits=64)
    algorithms: list[str] = []
    for hit in hits:
        algorithm = hit.get("algorithm")
        if algorithm and algorithm not in algorithms:
            algorithms.append(algorithm)
    return algorithms, len(hits)


# ── angr ─────────────────────────────────────────────────────────────


def angr_analysis(path: str) -> dict[str, Any]:
    """Recover functions with angr and attribute crypto constants to them.

    Uses only stable public API: ``angr.Project(path,
    auto_load_libs=False)``, ``CFGFast()``, ``cfg.kb.functions`` and
    ``project.factory.block(addr).bytes``.
    """
    try:
        import angr  # type: ignore[import-not-found]  # guarded by design
    except ImportError as exc:
        return {"tool": "angr", "available": False,
                "reason": f"angr not installed: {exc}",
                "functions": []}

    project = angr.Project(path, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    functions: list[CfaFunction] = []
    for func in cfg.kb.functions.values():
        if func.size <= 0:
            continue
        body = b""
        seen: set[int] = set()
        for block_addr in func.block_addrs:
            if block_addr in seen:
                continue
            seen.add(block_addr)
            body += project.factory.block(block_addr).bytes
        algorithms, hit_count = _attribute(body)
        functions.append(CfaFunction(func.name, func.addr, func.size,
                                     algorithms, hit_count))
    functions.sort(key=lambda f: (-f.hit_count, f.address))
    return {"tool": "angr", "available": True, "reason": None,
            "functions": [f.to_dict() for f in functions]}


# ── Ghidra ───────────────────────────────────────────────────────────


def _ghidra_headless() -> str | None:
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_dir:
        candidate = os.path.join(env_dir, "support", "analyzeHeadless")
        if os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("analyzeHeadless")


def ghidra_analysis(path: str, *, script_dir: str | None = None) -> dict[str, Any]:
    """Run Ghidra headless with the shipped post-script; parse its JSON.

    Contract: the post-script prints one JSON object as the LAST line of
    stdout — ``{"functions": [{"name", "address", "size", "algorithms",
    "hits"}, ...]}``. Anything else is an error, reported as such.
    """
    headless = _ghidra_headless()
    if headless is None:
        return {"tool": "ghidra", "available": False,
                "reason": "Ghidra not found: set GHIDRA_INSTALL_DIR or "
                          "put analyzeHeadless on PATH",
                "functions": []}
    script_dir = script_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))),
        "deploy", "ghidra")
    if not os.path.isfile(os.path.join(script_dir, GHIDRA_SCRIPT_NAME)):
        return {"tool": "ghidra", "available": False,
                "reason": f"post-script {GHIDRA_SCRIPT_NAME} missing from "
                          f"{script_dir}",
                "functions": []}

    import tempfile

    with tempfile.TemporaryDirectory(prefix="cfa-ghidra-") as project_dir:
        argv = [headless, project_dir, "CryptoScanCFA", "-import", path,
                "-scriptPath", script_dir, "-postScript", GHIDRA_SCRIPT_NAME,
                "-deleteProject"]
        result = subprocess.run(  # nosec B603 — fixed argv, no shell
            argv, capture_output=True, text=True, timeout=600, check=False)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or not lines:
        return {"tool": "ghidra", "available": False,
                "reason": f"analyzeHeadless failed rc={result.returncode}: "
                          f"{result.stderr.strip()[:400]}",
                "functions": []}
    try:
        payload = json.loads(lines[-1])
        functions = payload["functions"]
    except (ValueError, KeyError) as exc:
        return {"tool": "ghidra", "available": False,
                "reason": f"post-script output not parseable: {exc}",
                "functions": []}
    return {"tool": "ghidra", "available": True, "reason": None,
            "functions": functions}


# ── orchestration ────────────────────────────────────────────────────


def analyze(path: str, *, preferred: str | None = None) -> dict[str, Any]:
    """Analyze one binary; prefer one tool or take the first available."""
    order = [preferred] if preferred else ["angr", "ghidra"]
    attempts: list[dict[str, Any]] = []
    for tool in order:
        if tool == "angr":
            report = angr_analysis(path)
        elif tool == "ghidra":
            report = ghidra_analysis(path)
        else:
            raise ValueError(f"unknown tool: {tool}")
        if report["available"]:
            return {"model": "binary-cfa/v1", "path": path, **report,
                    "attempted": attempts}
        attempts.append({"tool": tool, "reason": report["reason"]})
    return {"model": "binary-cfa/v1", "path": path, "tool": None,
            "available": False,
            "reason": "; ".join(a["reason"] for a in attempts),
            "functions": [], "attempted": attempts}

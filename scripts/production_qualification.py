#!/usr/bin/env python3
"""Run the production qualification sequence without manufacturing evidence.

This is the operator-facing coordinator for the production-readiness work. It
runs the repository's existing checks and real-environment drills, keeps each
category separate, redacts command output, and writes a machine-readable report
plus a Markdown summary.

The default command is a safe preflight: it does not contact a customer
system, promote a database, or call an HSM. Live phases run only when their
required environment/configuration is present. Missing external evidence is
recorded as ``SKIP`` and never upgraded to ``PASS``.

Examples:
    # Safe repository/deployment preflight
    python scripts/production_qualification.py --phase preflight --out /tmp/qualification

    # Run the live API and integrations against a staging deployment
    QUALIFICATION_PASSWORD_FILE=/run/secrets/cryptoscan-admin \
    python scripts/production_qualification.py --phase deployment --api https://staging.example

    # Run all supplied real-environment evidence, but do not promote Postgres
    DR_PRIMARY_DSN=... DR_STANDBY_DSN=... \
    python scripts/production_qualification.py --phase all --out /secure/evidence/run-001

Use ``--strict`` only for release approval. It exits non-zero if any selected
phase is missing, skipped, or failed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts"


class Qualification:
    def __init__(self, out: Path, args: argparse.Namespace) -> None:
        self.out = out
        self.args = args
        self.rows: list[dict[str, Any]] = []
        self.started_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _redact(value: str) -> str:
        """Remove credentials from operator-visible output."""
        import re

        value = re.sub(r"(?i)(password|secret|token|api[_-]?key|private[_-]?key)=\S+", r"\1=[redacted]", value)
        value = re.sub(r"(://[^:/\s]+:)[^@\s]+(@)", r"\1[redacted]\2", value)
        return value[:2000]

    def record(self, category: str, status: str, detail: str, **extra: Any) -> None:
        row = {
            "category": category,
            "status": status,
            "detail": self._redact(detail),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        }
        self.rows.append(row)
        print(f"[{status:^6}] {category}: {row['detail']}")

    def command(self, category: str, command: list[str], *, env: dict[str, str] | None = None,
                cwd: Path | None = None, timeout: float = 900.0) -> int:
        """Run a qualification command and retain only bounded, redacted output."""
        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                cwd=str(cwd or ROOT),
                env={**os.environ, **(env or {})},
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.record(category, "FAIL", f"command timed out after {timeout:.0f}s", command=" ".join(command))
            return 124
        except OSError as exc:
            self.record(category, "FAIL", f"could not execute command: {type(exc).__name__}", command=" ".join(command))
            return 127
        output = self._redact((proc.stdout or "") + (proc.stderr or "")).strip()
        detail = f"exit={proc.returncode}; elapsed={time.monotonic() - started:.2f}s"
        if output:
            detail += f"; output={output[-700:]}"
        self.record(category, "PASS" if proc.returncode == 0 else "FAIL", detail, command=" ".join(command))
        return proc.returncode

    def artifact(self, category: str, path: Path | None, *, open_skips: bool = False) -> None:
        if path is None or not path.exists():
            self.record(category, "SKIP", "required external evidence artifact was not supplied")
            return
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            self.record(category, "FAIL", "evidence artifact is not valid JSON", artifact=str(path), sha256=digest)
            return
        statuses: list[str] = []
        if isinstance(payload, dict):
            if isinstance(payload.get("checks"), list):
                statuses.extend(str(row.get("status", row.get("verdict", ""))).upper() for row in payload["checks"] if isinstance(row, dict))
            if isinstance(payload.get("results"), list):
                statuses.extend(str(row.get("status", row.get("verdict", ""))).upper() for row in payload["results"] if isinstance(row, dict))
            for key in ("verdict", "status"):
                if payload.get(key):
                    statuses.append(str(payload[key]).upper())
        bad = {"FAIL", "FAILED", "ERROR", "SKIP", "PENDING", "NOT_RUN"}
        hard_failure = any(value in {"FAIL", "FAILED", "ERROR"} for value in statuses)
        # The engineering gate intentionally uses a top-level FAIL when a
        # release still has external SKIPs. For preflight reporting that is an
        # open qualification item, not a failed runtime check. Never apply this
        # relaxation to a supplied customer/provider artifact.
        if open_skips and hard_failure and isinstance(payload, dict):
            checks = payload.get("checks")
            nested = [str(row.get("status", "")).upper() for row in checks or [] if isinstance(row, dict)]
            hard_failure = any(value in {"FAIL", "FAILED", "ERROR"} for value in nested)
        status = "FAIL" if hard_failure else (
            "SKIP" if not statuses or any(value in bad for value in statuses) else "PASS"
        )
        self.record(category, status, f"artifact={path}; sha256={digest}; statuses={sorted(set(statuses))}", artifact=str(path), sha256=digest)

    def preflight(self) -> None:
        required = [
            ROOT / "docker-compose.yml",
            ROOT / "docker-compose.prod.yml",
            SCRIPT / "deploy_burn.py",
            SCRIPT / "burn_in.py",
            SCRIPT / "postgres_drill.py",
            SCRIPT / "hsm_qualification.py",
            SCRIPT / "soak.py",
            SCRIPT / "bank_readiness.py",
        ]
        missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
        self.record("preflight:qualification-assets", "PASS" if not missing else "FAIL",
                    "all qualification assets present" if not missing else f"missing={missing}")
        self.record("preflight:docker", "PASS" if shutil.which("docker") else "SKIP",
                    "docker is available" if shutil.which("docker") else "Docker is required for the production compose stack")
        self.record("preflight:production-env", "PASS" if os.getenv("ENVIRONMENT") == "production" else "SKIP",
                    "ENVIRONMENT=production" if os.getenv("ENVIRONMENT") == "production" else "not running inside a production environment; no deployment claim made")
        engineering = self.out / "engineering-gate.json"
        return_code = self.command("preflight:engineering-gate", [sys.executable, str(SCRIPT / "engineering_gate.py"), "--out", str(engineering)], timeout=180)
        if return_code and engineering.exists():
            try:
                payload = json.loads(engineering.read_text(encoding="utf-8"))
                checks = payload.get("checks") or []
                if checks and not any(str(row.get("status", "")).upper() in {"FAIL", "FAILED", "ERROR"} for row in checks if isinstance(row, dict)):
                    self.rows[-1]["status"] = "SKIP"
                    self.rows[-1]["detail"] += "; open external SKIPs remain"
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                pass
        self.artifact("preflight:engineering-artifact", engineering, open_skips=True)

    def deployment(self) -> None:
        api = self.args.api or os.getenv("QUALIFICATION_API")
        password_file = self.args.password_file or os.getenv("QUALIFICATION_PASSWORD_FILE")
        if not api or not password_file:
            self.record("deployment:full-surface-burn", "SKIP", "--api/QUALIFICATION_API and --password-file/QUALIFICATION_PASSWORD_FILE are required")
            return
        password_path = Path(password_file)
        if not password_path.is_file():
            self.record("deployment:full-surface-burn", "FAIL", "qualification password file does not exist")
            return
        password = password_path.read_text(encoding="utf-8").strip()
        if not password:
            self.record("deployment:full-surface-burn", "FAIL", "qualification password file is empty")
            return
        # A temporary argv-free environment file keeps the secret out of the
        # command line. deploy_burn reads DEPLOY_BURN_PASSWORD when present.
        env = {"DEPLOY_BURN_PASSWORD": password, "DEPLOY_BURN_API": api}
        self.command(
            "deployment:full-surface-burn",
            [sys.executable, str(SCRIPT / "deploy_burn.py"), "--api", api,
             "--out", str(self.out / "deploy-burn.md")],
            env=env,
            timeout=self.args.timeout,
        )

    def integrations(self) -> None:
        selected = self.args.integration or []
        if not selected:
            self.record("integrations:burn-in", "SKIP", "no --integration target supplied; use github, tls, smtp, neo4j, cloud, or container")
            return
        api = self.args.api or os.getenv("QUALIFICATION_API", "http://127.0.0.1:8010")
        env = {}
        password_file = self.args.password_file or os.getenv("QUALIFICATION_PASSWORD_FILE")
        if password_file and Path(password_file).is_file():
            env["BURN_IN_PASSWORD"] = Path(password_file).read_text(encoding="utf-8").strip()
        command = [sys.executable, str(SCRIPT / "burn_in.py"), "--api", api]
        for target in selected:
            command.extend(["--target", target])
        integration_dir = self.out / "integrations"
        integration_dir.mkdir(parents=True, exist_ok=True)
        self.command("integrations:burn-in", command, env=env, cwd=integration_dir, timeout=self.args.timeout)
        self.artifact("integrations:burn-in-artifact", integration_dir / "burn_in_report.json")

    def postgres_dr(self) -> None:
        if not os.getenv("DR_PRIMARY_DSN") or not os.getenv("DR_STANDBY_DSN"):
            self.record("postgresql-dr:promotion-and-restore", "SKIP", "DR_PRIMARY_DSN and DR_STANDBY_DSN are required; no DR claim made")
            return
        command = [sys.executable, str(SCRIPT / "postgres_drill.py"), "--out", str(self.out / "postgres-drill.json")]
        if self.args.execute_promotion:
            command.append("--execute-promotion")
            if self.args.acknowledge_destructive:
                command.append("--acknowledge-destructive")
        self.command("postgresql-dr:promotion-and-restore", command, timeout=self.args.timeout)
        self.artifact("postgresql-dr:artifact", self.out / "postgres-drill.json")

    def hsm(self) -> None:
        if not os.getenv("HSM_PROVIDER") or not os.getenv("HSM_KEY_ID"):
            self.record("hsm:provider-qualification", "SKIP", "HSM_PROVIDER and HSM_KEY_ID are required; local code cannot create provider evidence")
            return
        self.command(
            "hsm:provider-qualification",
            [sys.executable, str(SCRIPT / "hsm_qualification.py"), "--strict", "--out", str(self.out / "hsm-qualification.json")],
            timeout=self.args.timeout,
        )
        self.artifact("hsm:artifact", self.out / "hsm-qualification.json")

    def load_soak(self) -> None:
        if not self.args.soak_cycles and not self.args.soak_hours:
            self.record("load-soak:representative-run", "SKIP", "provide --soak-cycles or --soak-hours to run against a live deployment")
            return
        api = self.args.api or os.getenv("QUALIFICATION_API")
        password_file = self.args.password_file or os.getenv("QUALIFICATION_PASSWORD_FILE")
        if not api or not password_file or not Path(password_file).is_file():
            self.record("load-soak:representative-run", "SKIP", "live API and qualification password file are required")
            return
        env = {"SOAK_PASSWORD": Path(password_file).read_text(encoding="utf-8").strip()}
        command = [sys.executable, str(SCRIPT / "soak.py"), "--api", api, "--out", str(self.out / "soak")]
        if self.args.soak_cycles:
            command.extend(["--cycles", str(self.args.soak_cycles)])
        if self.args.soak_hours:
            command.extend(["--hours", str(self.args.soak_hours)])
        self.command("load-soak:representative-run", command, env=env, timeout=max(self.args.timeout, 3600))
        self.artifact("load-soak:summary", self.out / "soak" / "summary.json")

    def run(self, phase: str) -> int:
        self.out.mkdir(parents=True, exist_ok=True)
        phases = {
            "preflight": [self.preflight],
            "deployment": [self.preflight, self.deployment],
            "integrations": [self.preflight, self.integrations],
            "dr": [self.preflight, self.postgres_dr],
            "hsm": [self.preflight, self.hsm],
            "soak": [self.preflight, self.load_soak],
            "all": [self.preflight, self.deployment, self.integrations, self.postgres_dr, self.hsm, self.load_soak],
        }
        for step in phases[phase]:
            step()
        report = {
            "schema": "cryptoscan.production-qualification/1",
            "started_at": self.started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "phase": phase,
            "repository": self._repository_metadata(),
            "categories": self.rows,
            "boundary": "PASS requires real supplied infrastructure evidence. SKIP means the required external system or artifact was not supplied.",
        }
        report["verdict"] = "PASS" if self.rows and all(row["status"] == "PASS" for row in self.rows) else "FAIL"
        if any(row["status"] == "SKIP" for row in self.rows):
            report["verdict"] = "SKIP"
        path = self.out / "qualification.json"
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        md = self.out / "qualification.md"
        lines = ["# CryptoScan production qualification", "", f"Phase: `{phase}`", f"Verdict: **{report['verdict']}**", "", "| Category | Status | Detail |", "|---|---|---|"]
        lines.extend(f"| {row['category']} | {row['status']} | {row['detail']} |" for row in self.rows)
        lines.extend(["", "## Evidence boundary", "", report["boundary"]])
        md.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Qualification verdict: {report['verdict']} -> {path}")
        return 0 if report["verdict"] == "PASS" else (2 if report["verdict"] == "SKIP" else 1)

    @staticmethod
    def _repository_metadata() -> dict[str, Any]:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
        return {"commit": proc.stdout.strip(), "branch": os.getenv("GIT_BRANCH", "")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("preflight", "deployment", "integrations", "dr", "hsm", "soak", "all"), default="preflight")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--api", default=None)
    parser.add_argument("--password-file", default=None)
    parser.add_argument("--integration", action="append", choices=("github", "tls", "smtp", "neo4j", "cloud", "container"))
    parser.add_argument("--execute-promotion", action="store_true")
    parser.add_argument("--acknowledge-destructive", action="store_true")
    parser.add_argument("--soak-cycles", type=int, default=None)
    parser.add_argument("--soak-hours", type=float, default=None)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    result = Qualification(args.out, args).run(args.phase)
    if args.strict and result != 0:
        return 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())

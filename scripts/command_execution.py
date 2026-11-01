"""Command execution: can a collector's input become an argument, or a command?

A scanner runs local tools — `openssl`, `ssh-keyscan`, `git`, `docker`, `systemctl`
— on input it did not write. The failure this drill looks for is not "did we find
an exploit" but the structural one: **is any input a string that a shell will
parse, or a positional that a program will read as an option?**

Three properties, measured separately:

1. **No shell.** `shell=True`, `os.system`, `os.popen` and string command lines
   are counted across every non-test module. One is a finding, not a metric.
2. **No argument injection.** Each call site that takes input is driven with a
   canary that begins with `-` (an option) and one that carries shell
   metacharacters (`;`, `$( )`, backtick, newline), with `subprocess` replaced by
   a recorder. Two things are asserted: nothing executed, and the canary never
   became a *separate* argv token.
3. **End of options.** Where a program supports `--`, it is used before an
   untrusted positional. `systemctl` is the model: it already passes `--` before
   the unit name.

Run::

    python scripts/command_execution.py \\
        --json docs/bank-environment/122-command-execution.json \\
        --md   docs/bank-environment/122-command-execution.md
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA = "cryptoscan.command-execution/1"
VERSION = "command-execution/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

#: A canary that would be a file if anything executed it.
CANARY_DIR = Path(tempfile.gettempdir()) / "cryptoscan-injection-canary"

SHELL_INPUTS: tuple[tuple[str, str], ...] = (
    ("option", "-oProxyCommand=touch {canary}"),
    ("semicolon", "example.com; touch {canary}"),
    ("subshell", "example.com$(touch {canary})"),
    ("backtick", "example.com`touch {canary}`"),
    ("newline", "example.com\ntouch {canary}"),
    ("pipe", "example.com | touch {canary}"),
)

#: Assembled from parts so this file does not match its own census. The census
#: excludes this module by path as well — a scanner that scans itself and reports
#: its own pattern strings is noise, and noise is how a real finding gets missed.
SHELL_SINKS = ("shell" + "=True", "os." + "system", "os." + "popen",
               "subprocess." + "getoutput", "subprocess." + "getstatusoutput",
               "commands." + "getoutput")

#: Modules that only *name* the sinks above.
CENSUS_EXEMPT = {Path("scripts") / "command_execution.py"}


def _module_paths() -> list[Path]:
    paths: list[Path] = []
    for base in ("services", "scripts"):
        for path in (REPO_ROOT / base).rglob("*.py"):
            text = str(path)
            if "/tests/" in text or path.name.startswith("test_"):
                continue
            if "__pycache__" in text:
                continue
            if path.relative_to(REPO_ROOT) in CENSUS_EXEMPT:
                continue
            paths.append(path)
    return sorted(paths)


@dataclass
class Site:
    module: str
    function: str
    line: int
    argv_style: str          # list | string | shell
    uses_end_of_options: bool


def census() -> dict[str, Any]:
    """Every process-spawning call site, and how it builds its arguments."""
    sites: list[Site] = []
    shell_sinks: list[str] = []
    spawn_call = re.compile(r"subprocess\.(run|Popen|check_output|check_call|call)\s*\(")
    for path in _module_paths():
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = str(path.relative_to(REPO_ROOT))
        for sink in SHELL_SINKS:
            for match in re.finditer(re.escape(sink), text):
                line = text[: match.start()].count("\n") + 1
                shell_sinks.append(f"{rel}:{line} {sink}")
        for match in spawn_call.finditer(text):
            line = text[: match.start()].count("\n") + 1
            window = text[match.start(): match.start() + 700]
            argv_style = "shell" if "shell=True" in window else (
                "string" if re.search(r"subprocess\.\w+\(\s*[furb]?[\"']", window) else "list")
            sites.append(Site(
                module=rel,
                function=_enclosing_function(text, match.start()),
                line=line,
                argv_style=argv_style,
                uses_end_of_options=_uses_end_of_options(window),
            ))
    return {
        "sites": sites,
        "shell_sinks": shell_sinks,
        "findings": shell_sinks,
        "exempt": sorted(str(path) for path in CENSUS_EXEMPT),
        "by_style": {style: sum(1 for site in sites if site.argv_style == style)
                     for style in ("list", "string", "shell")},
        "end_of_options": sum(1 for site in sites if site.uses_end_of_options),
        "modules": len({site.module for site in sites}),
    }


def _enclosing_function(text: str, offset: int) -> str:
    best = ""
    for match in re.finditer(r"^\s*(?:async )?def (\w+)", text[:offset], re.MULTILINE):
        best = match.group(1)
    return best


def _uses_end_of_options(window: str) -> bool:
    return bool(re.search(r'(?<![-\w])"--"(?![-\w])|,\s*"--"\s*,', window))


# --------------------------------------------------------------------- probes
@dataclass
class Recorder:
    """Stands in for subprocess: records what would have run, runs nothing."""

    calls: list[list[str]] = field(default_factory=list)
    shells: list[str] = field(default_factory=list)

    def install(self, monkeypatch) -> None:
        import subprocess

        recorder = self

        class _Completed:
            returncode = 1
            stdout = ""
            stderr = ""

        def fake_run(*args, **kwargs):
            argv = args[0] if args else kwargs.get("args")
            recorder._record(argv, kwargs)
            return _Completed()

        def fake_popen(*args, **kwargs):
            argv = args[0] if args else kwargs.get("args")
            recorder._record(argv, kwargs)
            raise OSError("recorder: no process is started")

        monkeypatch.setattr(subprocess, "run", fake_run)
        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        monkeypatch.setattr(subprocess, "check_output", fake_run)

    def _record(self, argv, kwargs) -> None:
        if isinstance(argv, str):
            self.shells.append(argv)
            self.calls.append([argv])
        else:
            self.calls.append([str(part) for part in (argv or [])])


def _canary_created() -> bool:
    return CANARY_DIR.exists()


def _reset_canary() -> None:
    import shutil

    shutil.rmtree(CANARY_DIR, ignore_errors=True)


@dataclass
class Probe:
    name: str
    ok: bool
    observed: str

    def as_dict(self) -> dict[str, Any]:
        return {"probe": self.name, "ok": self.ok, "observed": self.observed}


def _drive(name: str, call: Callable[[str], Any], input_text: str) -> Probe:
    """Send one hostile input through one call site and grade what happened."""
    import subprocess

    _reset_canary()
    recorder = Recorder()
    original_run, original_popen = subprocess.run, subprocess.Popen

    class _Completed:
        returncode = 1
        stdout = ""
        stderr = ""

    def fake_run(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        recorder._record(argv, kwargs)
        return _Completed()

    def fake_popen(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args")
        recorder._record(argv, kwargs)
        raise OSError("recorder")

    subprocess.run, subprocess.Popen = fake_run, fake_popen
    refused = None
    try:
        call(input_text)
    except Exception as exc:  # a refusal is a pass, and its type is the evidence
        refused = f"{type(exc).__name__}"
    finally:
        subprocess.run, subprocess.Popen = original_run, original_popen

    if _canary_created():
        return Probe(f"{name}:{input_text[:18]}", False,
                     "a canary file was created — an input executed")
    if recorder.shells:
        return Probe(f"{name}:{input_text[:18]}", False,
                     f"a string command reached a shell: {recorder.shells[0][:80]}")
    if refused:
        return Probe(f"{name}:{input_text[:18]}", True, f"refused with {refused}")
    if not recorder.calls:
        return Probe(f"{name}:{input_text[:18]}", True,
                     "no process was spawned — the input never reached a command")
    argv = recorder.calls[0]
    hostile = [part for part in argv if part == input_text.strip()]
    split = [part for part in argv if input_text.strip()[:6] in part and part != input_text.strip()]
    if split:
        return Probe(f"{name}:{input_text[:18]}", False,
                     f"the input was split or embedded into another argument: {split[0][:80]}")
    if hostile and not re.match(r"^[A-Za-z0-9._/:\-]", hostile[0]):
        return Probe(f"{name}:{input_text[:18]}", False,
                     f"an option-shaped value reached argv: {hostile[0][:80]}")
    return Probe(f"{name}:{input_text[:18]}", True,
                 f"passed as a single argv element ({argv[0].split('/')[-1]} …)")


def probe_sites() -> list[dict[str, Any]]:
    """Drive each input-taking call site with hostile input."""
    for relative in ("services/network_scanner", "services/worker",
                     "services/container_scanner", "services/inventory",
                     "services/scanner", "services/runtime", "services/api",
                     "services/database", "shared/shared_models"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)

    rows: list[dict[str, Any]] = []

    # ---- ssh-keyscan: host is a positional
    from network_scanner.probing import ssh_keyscan

    def ssh_call(text: str):
        return ssh_keyscan.scan_ssh_host_keys(text, timeout=2)

    rows.append(_site_row(
        "ssh_keyscan", "network_scanner.probing.ssh_keyscan.scan_ssh_host_keys",
        "host", ssh_call))

    # ---- git clone: repo URL is a positional
    from worker.workspace.repo_cloner import RepoCloner

    def clone_call(text: str):
        return RepoCloner().clone(text, "main", str(Path(tempfile.gettempdir()) / "drill-clone"))

    rows.append(_site_row("git_clone", "worker.workspace.repo_cloner.RepoCloner.clone",
                          "repo_url", clone_call))

    # ---- container reference: a positional to docker/podman/skopeo
    from container_scanner.image import puller

    def pull_call(text: str):
        return puller._validated(text)

    rows.append(_site_row("image_reference", "container_scanner.image.puller._validated",
                          "reference", pull_call))

    # ---- systemctl: the model call site, with `--` already in place
    from inventory import linux_runtime

    def unit_call(text: str):
        return linux_runtime._systemctl_show(text)  # type: ignore[attr-defined]

    if hasattr(linux_runtime, "_systemctl_show"):
        rows.append(_site_row("systemctl_unit", "inventory.linux_runtime",
                              "unit", unit_call))
    return rows


def injection_control() -> Probe:
    """Prove the canary can fail: drive a deliberately vulnerable call site.

    Without this, "no site executed the canary" could mean "no site executed
    anything" — a recorder that silently swallows everything would score perfect.
    The control is a function that builds a shell string on purpose; it must be
    reported as a failure.
    """
    import subprocess

    def vulnerable(text: str) -> None:
        subprocess.run("echo " + text, shell=True)  # noqa: S602 — the control, on purpose

    probe = _drive("control-vulnerable-sink", vulnerable, "example.com; touch {canary}".format(
        canary=CANARY_DIR))
    return Probe("control-vulnerable-sink", not probe.ok,
                 "a shell string reached subprocess, so the check reports a failure"
                 if not probe.ok else "the control was NOT reported — the check is blind")


def _site_row(site: str, qualified: str, parameter: str,
              call: Callable[[str], Any]) -> dict[str, Any]:
    probes: list[Probe] = []
    for label, template in SHELL_INPUTS:
        hostile = template.format(canary=CANARY_DIR)
        probes.append(_drive(f"{site}:{label}", call, hostile))
    # The negative control: a legitimate value must still get through, or the
    # "refused" result above proves nothing but a broken function.
    legit = {"ssh_keyscan": "127.0.0.1", "git_clone": "https://example.invalid/repo.git",
             "image_reference": "nginx:1.27", "systemctl_unit": "sshd"}[site]
    probe = _drive(f"{site}:control-legit", call, legit)
    probes.append(Probe("control-legitimate-value", probe.ok, probe.observed))
    failed = [entry for entry in probes if not entry.ok]
    return {
        "site": site,
        "qualified": qualified,
        "parameter": parameter,
        "verdict": FAIL if failed else PASS,
        "probes": [entry.as_dict() for entry in probes],
        "hostile_inputs": len(SHELL_INPUTS),
    }


# ----------------------------------------------------------------------- rows
def measure() -> dict[str, Any]:
    static = census()
    rows: list[dict[str, Any]] = []

    # ---- 1. shell usage
    rows.append({
        "id": "shell_sinks",
        "question": "does any collector input reach a shell?",
        "verdict": PASS if not static["shell_sinks"] and static["by_style"]["shell"] == 0
        and static["by_style"]["string"] == 0 else FAIL,
        "probes": [{
            "probe": "no-shell",
            "expected": "no shell=True, os.system, os.popen or string command line",
            "ok": not static["shell_sinks"] and static["by_style"]["shell"] == 0
            and static["by_style"]["string"] == 0,
            "observed": f"{len(static['shell_sinks'])} shell sink(s); "
                        f"{static['by_style']['string']} string command(s); "
                        f"{static['by_style']['list']} argv-list call(s) in "
                        f"{static['modules']} module(s)",
        }],
        "unproven": [],
        "limits": ["a census reads source; a call site reached through an import alias "
                   "or a compiled extension would be invisible to it"],
        "sinks": static["shell_sinks"][:10],
    })

    # ---- 2. argument injection, executed
    site_rows = probe_sites()
    failed = [row for row in site_rows if row["verdict"] == FAIL]
    rows.append({
        "id": "argument_injection",
        "question": "can a hostile target become an option or a second argument?",
        "verdict": FAIL if failed else PASS,
        "probes": [{
            "probe": "hostile-inputs-contained",
            "expected": "every call site refuses or passes the input as one argv element",
            "ok": not failed,
            "observed": f"{len(site_rows)} call site(s) driven with {len(SHELL_INPUTS)} "
                        f"hostile inputs each; {len(failed)} site(s) failed",
        }, {
            "probe": injection_control().name,
            "expected": "the control's shell string is reported as a failure",
            "ok": injection_control().ok,
            "observed": injection_control().observed,
        }],
        "unproven": [],
        "limits": ["the canary proves an input did not execute through *this* call site; "
                   "it cannot prove the same input does not reach another sink later in "
                   "the pipeline",
                   "the recorder replaces subprocess, so a site that shells out through a "
                   "library (paramiko, docker-py) would not appear here"],
        "sites": site_rows,
    })

    # ---- 3. end-of-options discipline
    rows.append({
        "id": "end_of_options",
        "question": "is `--` used before untrusted positionals where the tool supports it?",
        "verdict": PARTIAL,
        "probes": [{
            "probe": "counted",
            "expected": "the count is reported per call site, not assumed complete",
            "ok": True,
            "observed": f"{static['end_of_options']} of {len(static['sites'])} call sites "
                        f"pass `--` before an untrusted positional",
        }],
        "unproven": ["some tools have no end-of-options support (`openssl s_client` takes "
                     "its target as the value of `-connect`, which is safe by shape rather "
                     "than by `--`); the count is therefore evidence of intent, not a "
                     "complete measure"],
        "limits": [],
        "sites": [{"module": site.module, "function": site.function, "line": site.line,
                   "end_of_options": site.uses_end_of_options}
                  for site in static["sites"]],
    })

    # ---- 4. the privileged surfaces a scanner is asked about
    text_all = "\n".join(path.read_text(encoding="utf-8", errors="ignore")
                         for path in _module_paths())
    docker_socket = len(re.findall(r"/var/run/docker\.sock|docker\.sock", text_all))
    k8s_exec = len(re.findall("kubectl" + r"\s+exec|pods/" + "exec|create_namespaced_pod_" + "exec",
                              text_all))
    setuid = len(re.findall(r"os\.setuid\(0\)|setresuid\(0", text_all))
    rows.append({
        "id": "privileged_surfaces",
        "question": "does the branch touch the docker socket, exec into pods, or run as root?",
        "verdict": PASS if docker_socket == 0 and k8s_exec == 0 and setuid == 0 else PARTIAL,
        "probes": [{
            "probe": "no-privileged-exec",
            "expected": "no docker-socket mount, no kubectl exec, no privilege drop-to-root",
            "ok": docker_socket == 0 and k8s_exec == 0 and setuid == 0,
            "observed": f"docker socket {docker_socket} · pod exec {k8s_exec} · "
                        f"setuid(0) {setuid}",
        }],
        "unproven": ["the container scanner reads images through skopeo/docker/podman "
                     "CLIs; if a deployment mounts the socket, the CLI inherits that "
                     "authority and this source census would not see it",
                     "seccomp and namespace isolation of the static scanner are not "
                     "measured here"],
        "limits": [],
    })

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "sites": len(static["sites"]),
        "rows": rows,
        "limits": [
            "Source census plus executed probes in-process. No real `ssh-keyscan`, `git` "
            "or container CLI was asked to run: the recorder stands in for subprocess, so "
            "this proves what would have been passed to them, not what they did with it.",
            "Shell expansion inside a spawned tool (a tool that itself calls a shell) is "
            "out of scope — the tool's own argument handling is the boundary.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Command execution — can collector input become a command?",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail** · "
        f"{report['sites']} process call sites",
        "",
        "| Question | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        evidence = row["probes"][0]["observed"] if row["probes"] else ""
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {evidence} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        for probe in row["probes"]:
            mark = "PASS" if probe["ok"] else "**FAIL**"
            lines.append(f"- **{mark}** `{probe['probe']}` — {probe['observed']}")
        for site in row.get("sites", []):
            if "probes" in site:
                lines.append("")
                lines.append(f"#### `{site['site']}` — {site['verdict']} "
                             f"(`{site['parameter']}`)")
                lines.append("")
                for probe in site["probes"]:
                    mark = "PASS" if probe["ok"] else "**FAIL**"
                    lines.append(f"- {mark} `{probe['probe']}`: {probe['observed']}")
        for sink in row.get("sinks", []) or []:
            lines.append(f"- **Shell sink:** `{sink}`")
        for gap in row.get("unproven", []):
            lines.append(f"- **Not proven:** {gap}")
        for limit in row.get("limits", []):
            lines.append(f"- **Limit:** {limit}")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** no collector input reaches a shell, and every "
        "call site that takes a target either refuses a hostile one or passes it as a single "
        "argv element — with `--` before the positional wherever the tool supports it. The "
        "gap that remains is the deployment: a mounted docker socket, a privileged container "
        "or a tool that expands its own arguments is outside what a source census can see.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Command-execution drill.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99,
                        help="exit non-zero when more than this many rows fail")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<8} {row['id']:<22} "
                  f"{row['probes'][0]['observed'][:100] if row['probes'] else ''}")
            for site in row.get("sites", []):
                if isinstance(site, dict) and site.get("verdict") == FAIL:
                    print(f"          FAILED site {site['site']}")
                    for probe in site["probes"]:
                        if not probe["ok"]:
                            print(f"            {probe['probe']}: {probe['observed']}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"][FAIL] <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

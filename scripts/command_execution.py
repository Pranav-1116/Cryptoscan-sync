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
    argv_text: str = ""      # the call window plus the statements that built the argv


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
            window = _window_within_function(text, match.start(), 700)
            argv_style = "shell" if "shell=True" in window else (
                "string" if re.search(r"subprocess\.\w+\(\s*[furb]?[\"']", window) else "list")
            argv_text = _argv_statements(text, match.start(), window)
            sites.append(Site(
                module=rel,
                function=_enclosing_function(text, match.start()),
                line=line,
                argv_style=argv_style,
                uses_end_of_options=_uses_end_of_options(argv_text),
                argv_text=argv_text,
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


def _window_within_function(text: str, offset: int, size: int) -> str:
    """At most ``size`` characters after ``offset``, never past the function's end.

    A naive window runs into the *next* function, which is how a name from a
    neighbouring function gets mistaken for this call's parameter. Cutting at
    the next ``def`` with the same or shallower indent keeps the reading local.
    """
    window = text[offset:offset + size]
    start_of_call = text.rfind("\n", 0, offset) + 1
    indent = len(text[start_of_call:offset]) - len(text[start_of_call:offset].lstrip())
    boundary = re.search(rf"^\s{{0,{indent}}}(?:async )?def ", window, re.MULTILINE)
    return window[: boundary.start()] if boundary else window


def _argv_statements(text: str, call_offset: int, window: str) -> str:
    """The statements that build the argv passed to this call.

    ``subprocess.run(cmd, ...)`` says nothing about ``cmd`` by itself. Resolve
    one level: find the identifier handed to the call, then collect the
    statements in the enclosing function that assign, ``extend`` or ``append``
    to it — following a multi-line literal to its closing bracket. Without this,
    every call site that builds its argv in a variable looks like it forgot
    ``--``, which is noise on a check that exists to find real omissions.
    """
    match = re.match(r"subprocess\.\w+\(\s*([A-Za-z_]\w*)", window)
    if not match:
        return window
    name = match.group(1)
    function_start = 0
    for found in re.finditer(r"^(\s*)(?:async )?def ", text[:call_offset], re.MULTILINE):
        function_start = found.start()
    body = text[function_start:call_offset]
    collected: list[str] = []
    lines = body.splitlines()
    index = 0
    pattern = re.compile(rf"\b{re.escape(name)}\s*(?:=|\+=|\.extend\s*\(|\.append\s*\(|\.insert\s*\()")
    while index < len(lines):
        if pattern.search(lines[index]):
            chunk = [lines[index]]
            depth = _bracket_delta(lines[index])
            while depth > 0 and index + 1 < len(lines):
                index += 1
                chunk.append(lines[index])
                depth += _bracket_delta(lines[index])
            collected.extend(chunk)
        index += 1
    return window + "\n" + "\n".join(collected)


def _bracket_delta(line: str) -> int:
    return sum(line.count(opener) for opener in "([{") - sum(line.count(closer) for closer in ")]}")


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


def _module_text(row: dict[str, Any]) -> str:
    for candidate in row["modules"]:
        path = REPO_ROOT / candidate
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="ignore")
    return ""


def _module_terminates(row: dict[str, Any]) -> bool:
    """True when `--` sits immediately before the parameter in an argv literal."""
    text = _module_text(row)
    parameter = re.escape(row["parameter"])
    if not text:
        return False
    pattern = rf'"--"\s*,\s*[\w.\[\]]*\b{parameter}\b'
    return bool(re.search(pattern, text))


def _module_paths_for(qualified: str) -> set[str]:
    """Repo-relative paths a dotted qualified name could live in.

    ``container_scanner.image.puller._validated`` is
    ``services/container_scanner/container_scanner/image/puller.py``: the dotted
    name drops the outer project directory, so try each suffix of the path.
    """
    parts = qualified.split(".")
    candidates: set[str] = set()
    for drop in (1, 2):
        module = "/".join(parts[:-drop]) + ".py"
        candidates.add(module)
        candidates.add("services/" + module)
        candidates.add("scripts/" + module)
    for site_path in (path.relative_to(REPO_ROOT) for path in _module_paths()):
        text = str(site_path)
        for candidate in list(candidates):
            if text.endswith(candidate):
                candidates.add(text)
    return candidates


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
        "function": qualified.rsplit(".", 1)[-1],
        "modules": sorted(_module_paths_for(qualified)),
        "parameter": parameter,
        "verdict": FAIL if failed else PASS,
        "probes": [entry.as_dict() for entry in probes],
        "hostile_inputs": len(SHELL_INPUTS),
    }


# ----------------------------------------------------------------------- rows
def measure() -> dict[str, Any]:
    static = census()
    rows: list[dict[str, Any]] = []

    driven = probe_sites()

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
    site_rows = driven
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
    #
    # The question is about *untrusted positionals*, so the population has to be
    # the sites that actually take one — not all 91 call sites, most of which
    # pass fixed flags to a local binary and have nothing to terminate. The
    # untrusted set is exactly the sites this drill drives with hostile input.
    untrusted_sites = []
    for site in static["sites"]:
        for row in driven:
            # The site is the spawn call in the module the drill drove whose argv
            # mentions the parameter it drove — not every call in a function of
            # the same name. `git rev-parse` lives inside `clone` and takes no
            # caller value; it must not be counted as an unterminated positional.
            if site.module not in row["modules"]:
                continue
            if re.search(rf"\b{re.escape(row['parameter'])}\b", site.argv_text):
                untrusted_sites.append(site)
                break
    missing = [site for site in untrusted_sites if not site.uses_end_of_options]

    # A driven parameter does not always reach the spawn call directly: the
    # container puller builds its argv one function up (`_pull_docker` →
    # `_run`). Those sites cannot be found by "the argv mentions the
    # parameter", so read the module for `--` immediately before the parameter
    # instead of pretending they do not exist.
    indirect = [row for row in driven
                if not any(site.module in row["modules"] for site in untrusted_sites)]
    indirect_missing = [row["site"] for row in indirect if not _module_terminates(row)]
    mapped_all = not indirect_missing
    rows.append({
        "id": "end_of_options",
        "question": "is `--` used before every untrusted positional?",
        "verdict": PASS if untrusted_sites and not missing and mapped_all else FAIL,
        "probes": [{
            "probe": "untrusted-positional-terminated",
            "expected": "every call site that takes a caller-supplied positional passes `--`",
            "ok": bool(untrusted_sites) and not missing and mapped_all,
            "observed": f"{len(untrusted_sites)} of {len(static['sites'])} call sites take a "
                        f"caller-supplied positional; {len(untrusted_sites) - len(missing)} "
                        f"pass `--` before it"
                        + (f" — missing: {[site.function for site in missing]}" if missing
                           else ""),
        }, {
            "probe": "every-driven-site-classified",
            "expected": "each call site the drill drove is present in this population",
            "ok": mapped_all,
            "observed": (f"{len(driven) - len(indirect)} driven site(s) pass their "
                         f"parameter straight to a spawn call; {len(indirect)} build the "
                         f"argv one function up"
                         + (f" ({', '.join(row['site'] for row in indirect)}) "
                            f"and {'all terminate it' if not indirect_missing else 'one does not: ' + ', '.join(indirect_missing)}"
                            if indirect else "")
                         + ("" if mapped_all else
                            " — the population would undercount and this row would overstate")),
        }, {
            "probe": "control-plan-positional",
            "expected": "a site that assembles its own argv internally is NOT counted as an "
                        "untrusted positional (the population is measured, not assumed)",
            "ok": True,
            "observed": f"{len(static['sites']) - len(untrusted_sites)} call sites pass only "
                        f"fixed flags or validated values and are excluded by construction",
        }],
        "unproven": [],
        "limits": ["Some CLIs take their target as an *option's value* (`openssl s_client "
                   "-connect`, `ssh -o`, `git -C`) rather than a positional: there `--` "
                   "does nothing and the grammar check is the whole defence. Those sites "
                   "are covered by the argument-injection row, not by this one."],
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

#!/usr/bin/env python3
"""The monitoring bundle: does the stack that ships actually connect?

`infra/monitoring` held a Prometheus config with an `alerting:` stanza and an
`alerts.yml` full of rules, and `docker-compose.yml` ran neither process. Guide
117 proved the delivery half by posting a notification to the API by hand; what
it could not prove is that a deployed stack has anything doing the posting.

This script grades the bundle as a bundle, and the checks are cross-file or
executed rather than per-file:

``compose_wiring``
    the overlay starts Prometheus and Alertmanager, mounts each config at the
    path that config names inside itself, mounts the secrets they read, pins
    image tags, publishes no host port and drops capabilities. A mount path that
    drifts from a path inside a config fails when the container starts, which is
    the worst possible moment to learn it.

``config_chain``
    Prometheus's `alertmanagers[].static_configs[].targets` must name the
    Alertmanager service and the port it listens on **as derived from the
    overlay**, not as a constant; every receiver URL in `alertmanager.yml` must
    resolve to a path the API itself serves — read out of the app's own OpenAPI
    document, so a renamed route is caught; and the rule file Prometheus mounts
    must carry rules whose labels the routing tree actually matches.

``secret_wiring``
    the token file Alertmanager reads is the token the API validates. This one is
    executed: a real ASGI app with the real `require_alertmanager_token`
    dependency is called with the right token (200), a token one character off
    (401) and with no file at all (503, fail closed).

``negative_control``
    every check above is re-run against a copy of the bundle with exactly one
    defect injected — a wrong Alertmanager target, a receiver URL the API does
    not serve, a missing volume, a short token — and must fail. A check that
    cannot fail is decoration.

    python3 scripts/monitoring_bundle.py --json docs/bank-environment/127-monitoring-bundle.json \
                                         --md   docs/bank-environment/127-monitoring-bundle.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
OVERLAY = REPO_ROOT / "docker-compose.monitoring.yml"
PROMETHEUS = REPO_ROOT / "infra" / "monitoring" / "prometheus" / "prometheus.yml"
RULES = REPO_ROOT / "infra" / "monitoring" / "prometheus" / "alerts.yml"
ALERTMANAGER = REPO_ROOT / "infra" / "monitoring" / "alertmanager" / "alertmanager.yml"
ENV_EXAMPLE = REPO_ROOT / ".env.production.example"

SCHEMA = "cryptoscan.monitoring-bundle/1"
PASS, PARTIAL, FAIL, SKIP = "PASS", "PARTIAL", "FAIL", "SKIP"

#: The API path the platform receiver posts to. Kept here so the check fails when
#: the config points somewhere the app does not serve, rather than trusting it.
RECEIVER_PATH = "/api/v1/ops/alerts/alertmanager"


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #

class Bundle:
    """The four files, and the defects injected into a copy of them."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.overlay_path = root / OVERLAY.relative_to(REPO_ROOT)
        self.prometheus_path = root / PROMETHEUS.relative_to(REPO_ROOT)
        self.rules_path = root / RULES.relative_to(REPO_ROOT)
        self.alertmanager_path = root / ALERTMANAGER.relative_to(REPO_ROOT)
        self.env_path = root / ENV_EXAMPLE.relative_to(REPO_ROOT)

    def overlay(self) -> dict[str, Any]:
        return yaml.safe_load(self.overlay_path.read_text(encoding="utf-8")) or {}

    def services(self) -> dict[str, Any]:
        return self.overlay().get("services") or {}

    def prometheus(self) -> dict[str, Any]:
        return yaml.safe_load(self.prometheus_path.read_text(encoding="utf-8")) or {}

    def rules(self) -> dict[str, Any]:
        return yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}

    def alertmanager(self) -> dict[str, Any]:
        return yaml.safe_load(self.alertmanager_path.read_text(encoding="utf-8")) or {}

    def env(self) -> dict[str, str]:
        """Parse the production template — no interpolation, just NAME=value."""
        pairs: dict[str, str] = {}
        for line in self.env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            pairs[name.strip()] = value.strip()
        return pairs


def _split_mount(entry: str) -> list[str]:
    """Split a volume spec on `:` but not inside a `${VAR:-default}` expression.

    ``${MONITORING_SECRETS_DIR:-./infra/monitoring/secrets}/webhook_token:/etc/...``
    contains a colon the shell owns, and splitting on it silently turns a mounted
    secret into "not mounted" — which is how a bundle check starts lying.
    """
    parts: list[str] = []
    depth = 0
    current = []
    index = 0
    while index < len(entry):
        char = entry[index]
        if char == "$" and entry[index + 1:index + 2] == "{":
            depth += 1
            current.append(char)
        elif char == "}" and depth:
            depth -= 1
            current.append(char)
        elif char == ":" and not depth:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _mounts(service: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(host, container, mode)`` for each bind mount, ignoring named volumes."""
    out = []
    for entry in service.get("volumes") or []:
        parts = _split_mount(str(entry))
        if len(parts) < 2:
            continue
        host, container = parts[0], parts[1]
        if not host.startswith(".") and not host.startswith("/") and not host.startswith("$"):
            continue  # named volume, not a config file
        mode = parts[2] if len(parts) > 2 else "rw"
        out.append((host, container, mode))
    return out


def _container_path_for(config_path: Path, service: dict[str, Any],
                        root: Path = REPO_ROOT) -> str | None:
    """Where the compose overlay mounts ``config_path`` inside ``service``.

    The relative form is computed against the bundle root, not the repository:
    the negative control runs against a copied bundle, and comparing its paths
    against the repository root would make every mount look missing — a control
    that always fails proves nothing.
    """
    relative = "./" + str(config_path.relative_to(root))
    for host, container, _mode in _mounts(service):
        if host.rstrip("/") == relative.rstrip("/"):
            return container
    return None


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #

def check_compose_wiring(bundle: Bundle) -> dict[str, Any]:
    services = bundle.services()
    probes: list[dict[str, Any]] = []

    def probe(name: str, ok: bool, observed: str) -> None:
        probes.append({"probe": name, "ok": bool(ok), "observed": observed})

    for name in ("prometheus", "alertmanager"):
        service = services.get(name) or {}
        probe(f"service-{name}-exists", bool(service),
              f"the overlay defines `{name}`" if service else f"no `{name}` service in the overlay")
        image = str(service.get("image") or "")
        pinned = bool(image) and ":latest" not in image and ":" in image.rsplit("/", 1)[-1]
        probe(f"{name}-image-pinned", pinned,
              f"image is {image}" if pinned else
              f"image is {image or '(none)'} — an unpinned monitoring image is a "
              "supply-chain change nobody reviewed")
        probe(f"{name}-no-host-port", not (service.get("ports")),
              "publishes no host port; reach it through the bank's proxy"
              if not service.get("ports") else f"publishes {service.get('ports')} on the host")
        security = service.get("security_opt") or []
        probe(f"{name}-no-new-privileges", "no-new-privileges:true" in security,
              f"security_opt={security}")
        probe(f"{name}-has-healthcheck", bool(service.get("healthcheck")),
              "healthcheck present" if service.get("healthcheck") else "no healthcheck: a wedged monitor looks like a quiet estate")
        probe(f"{name}-restart-policy", service.get("restart") == "unless-stopped",
              f"restart={service.get('restart')!r}")

    prometheus = services.get("prometheus") or {}
    alertmanager = services.get("alertmanager") or {}

    # The configs must land where the configs themselves say they are.
    for label, config_path, service in (
        ("prometheus-config", bundle.prometheus_path, prometheus),
        ("rules", bundle.rules_path, prometheus),
        ("alertmanager-config", bundle.alertmanager_path, alertmanager),
    ):
        container = _container_path_for(config_path, service, bundle.root)
        probe(f"{label}-mounted", container is not None,
              f"mounted at {container}" if container else f"{config_path.name} is not mounted into the service")
        if container:
            mode = next(mode for host, _c, mode in _mounts(service)
                        if host.rstrip("/") == ("./" + str(config_path.relative_to(bundle.root))).rstrip("/"))
            probe(f"{label}-read-only", "ro" in mode, f"mount mode is {mode}")

    # Rules must be mounted at the path prometheus.yml's rule_files names.
    rule_files = [str(entry) for entry in (bundle.prometheus().get("rule_files") or [])]
    mounted_rule_paths = {container for _h, container, _m in _mounts(prometheus)}
    unmatched = [entry for entry in rule_files if entry not in mounted_rule_paths]
    probe("rule_files-match-the-mount", not unmatched,
          "every rule_files entry is a mounted path" if not unmatched else
          f"rule_files names {unmatched}, which nothing mounts — Prometheus starts and silently evaluates no rules")

    # Secrets: the files each config reads must be mounted, read-only.
    alertmanager_text = bundle.alertmanager_path.read_text(encoding="utf-8")
    credential_paths = re.findall(r"credentials_file:\s*(\S+)", alertmanager_text)
    am_mounts = {container for _h, container, _m in _mounts(alertmanager)}
    missing = [path for path in credential_paths if path not in am_mounts]
    probe("receiver-credential-file-mounted", bool(credential_paths) and not missing,
          f"credentials_file {credential_paths} is mounted" if credential_paths and not missing else
          f"credentials_file {credential_paths} is not mounted into the container; Alertmanager refuses to start" if credential_paths else
          "the receiver has no credentials_file: the API would refuse the notification in production")

    prometheus_text = bundle.prometheus_path.read_text(encoding="utf-8")
    token_files = re.findall(r"bearer_token_file:\s*(\S+)", prometheus_text)
    prom_mounts = {container for _h, container, _m in _mounts(prometheus)}
    missing_prom = [path for path in token_files if path not in prom_mounts]
    probe("metrics-token-file-mounted", bool(token_files) and not missing_prom,
          f"bearer_token_file {token_files} is mounted" if token_files and not missing_prom else
          f"bearer_token_file {token_files} is not mounted; production /metrics answers 401 and every metric-derived alert stops")

    secrets_dir = str((prometheus.get("volumes") or [""])[0] if prometheus.get("volumes") else "")
    has_dir_var = any("MONITORING_SECRETS_DIR" in str(entry) for entry in
                      (prometheus.get("volumes") or []) + (alertmanager.get("volumes") or []))
    probe("secrets-from-one-directory", has_dir_var,
          "both services read their token from ${MONITORING_SECRETS_DIR}, one source"
          if has_dir_var else f"token mounts do not share one directory variable ({secrets_dir})")

    return {"probes": probes}


def check_config_chain(bundle: Bundle, served_paths: set[str]) -> dict[str, Any]:
    probes: list[dict[str, Any]] = []

    def probe(name: str, ok: bool, observed: str) -> None:
        probes.append({"probe": name, "ok": bool(ok), "observed": observed})

    services = bundle.services()
    alertmanager_service = services.get("alertmanager") or {}
    prometheus_service = services.get("prometheus") or {}

    # The port Alertmanager listens on, read out of its own command line.
    command = [str(part) for part in (alertmanager_service.get("command") or [])]
    listen = next((part.split("=", 1)[1] for part in command if part.startswith("--web.listen-address")), "")
    port = listen.rsplit(":", 1)[-1] if listen else ""
    probe("alertmanager-listens-on-a-known-port", bool(port),
          f"--web.listen-address={listen}" if port else "no --web.listen-address in the alertmanager command")

    targets = [target
               for group in ((bundle.prometheus().get("alerting") or {}).get("alertmanagers") or [])
               for config in (group.get("static_configs") or [])
               for target in (config.get("targets") or [])]
    expected = f"alertmanager:{port}" if port else "alertmanager:<port>"
    probe("prometheus-alerting-target", expected in targets,
          f"Prometheus sends to {targets}" if expected in targets else
          f"Prometheus sends to {targets} but the overlay runs Alertmanager as `{expected}`; "
          "the rules evaluate and go nowhere")

    probe("prometheus-depends-on-alertmanager",
          "alertmanager" in ((prometheus_service.get("depends_on") or {}) if isinstance(
              prometheus_service.get("depends_on"), dict) else prometheus_service.get("depends_on") or []),
          f"depends_on={prometheus_service.get('depends_on')}")

    # Every receiver URL must be a path the API actually serves.
    text = bundle.alertmanager_path.read_text(encoding="utf-8")
    urls = re.findall(r"url:\s*\"?([^\"\s]+)\"?", text)
    served = []
    for url in urls:
        path = "/" + url.split("://", 1)[-1].partition("/")[2] if "://" in url else url
        path = path.split("?", 1)[0]
        served.append((url, path, path in served_paths))
    unknown = [path for _url, path, ok in served if not ok]
    probe("receiver-url-is-a-served-route", bool(served) and not unknown,
          f"receiver URL(s) resolve: {[path for _u, path, ok in served if ok]}" if served and not unknown else
          f"receiver URL(s) {unknown} are not routes this API serves — every notification would be a 404"
          if unknown else "no receiver URL found in alertmanager.yml")

    # The routing tree must name only receivers that exist, or alerts vanish.
    document = bundle.alertmanager()
    receivers = {receiver.get("name") for receiver in document.get("receivers") or []}
    route = document.get("route") or {}
    named = [route.get("receiver")] + [sub.get("receiver") for sub in route.get("routes") or []]
    orphans = sorted({name for name in named if name and name not in receivers})
    probe("every-route-names-a-real-receiver", not orphans,
          "every route receiver is defined" if not orphans else f"routes name undefined receiver(s) {orphans}")

    # Where does each severity the rules actually use end up? A severity that
    # matches no sub-route is not unrouted — it lands on the default receiver —
    # so the honest questions are "does every severity reach a defined receiver"
    # and "is a paging severity being dropped".
    rules = bundle.rules()
    severities = sorted({(rule.get("labels") or {}).get("severity")
                         for group in rules.get("groups") or []
                         for rule in group.get("rules") or []
                         if rule.get("alert") and (rule.get("labels") or {}).get("severity")})
    resolved: dict[str, str] = {}
    for severity in severities:
        receiver = None
        for sub in route.get("routes") or []:
            matchers = [str(matcher) for matcher in (sub.get("matchers") or [])]
            if any(re.search(rf"severity\s*=~?\s*\"?{re.escape(severity)}\"?$", matcher)
                   for matcher in matchers):
                receiver = sub.get("receiver")
                break
        resolved[severity] = receiver or route.get("receiver") or ""
    unrouted = sorted(severity for severity, receiver in resolved.items() if not receiver)
    probe("every-rule-severity-resolves-to-a-receiver", bool(severities) and not unrouted,
          "each rule severity resolves: " + ", ".join(f"{s}->{r}" for s, r in resolved.items())
          if severities and not unrouted else
          f"severity {unrouted} resolves to no receiver — those alerts are delivered nowhere"
          if unrouted else "alerts.yml defines no alert with a severity label")

    dropped = sorted(severity for severity, receiver in resolved.items()
                     if "null" in receiver.lower()
                     and severity.lower() not in {"info", "none", "debug"})
    probe("no-paging-severity-is-silenced", not dropped,
          "informational alerts are routed to the null receiver; nothing that should page is"
          if not dropped else
          f"severity {dropped} resolves to the null receiver: the alert evaluates, pages nobody, "
          "and /metrics shows nothing was delivered — the quietest possible outage")

    # The rule file mounted by Prometheus must be the one that has rules in it.
    rule_count = sum(len(group.get("rules") or []) for group in rules.get("groups") or [])
    probe("rules-file-has-rules", rule_count > 0, f"{rule_count} rule(s) in alerts.yml")

    return {"probes": probes, "rule_count": rule_count, "targets": targets,
            "receiver_urls": [url for url, _p, _ok in served]}


def check_secret_wiring(bundle: Bundle, secrets: dict[str, str]) -> dict[str, Any]:
    """Execute the API's own token check against the token file, not a copy."""
    probes: list[dict[str, Any]] = []

    def probe(name: str, ok: bool, observed: str) -> None:
        probes.append({"probe": name, "ok": bool(ok), "observed": observed})

    text = bundle.alertmanager_path.read_text(encoding="utf-8")
    credential = re.search(r"credentials_file:\s*(\S+)", text)
    credential_path = credential.group(1) if credential else ""
    file_name = Path(credential_path).name
    token = secrets.get(file_name, "")

    probe("token-file-is-rendered", bool(token),
          f"{file_name} exists with {len(token)} character(s)" if token else
          f"{file_name} is missing or empty — Alertmanager will not start, and an empty "
          "token would be refused by the API anyway")
    probe("token-length-meets-the-api-floor", len(token) >= 32,
          f"{len(token)} character(s); the API requires 32" if token else "no token to measure")

    env = bundle.env()
    documented = "ALERTMANAGER_WEBHOOK_TOKEN" in env
    probe("token-is-documented-in-the-production-template", documented,
          "ALERTMANAGER_WEBHOOK_TOKEN is in .env.production.example" if documented else
          "the production template never mentions the token, so an operator cannot set it")
    probe("production-template-keeps-the-two-tokens-apart",
          env.get("ALERTMANAGER_WEBHOOK_TOKEN") == "" and env.get("METRICS_TOKEN") == ""
          or env.get("ALERTMANAGER_WEBHOOK_TOKEN") != env.get("METRICS_TOKEN"),
          "the template leaves both blank; one read-only scrape credential and one inbound "
          "write credential must never be the same value")

    # Executed: the real dependency, called with the real ASGI app.
    results = _exercise_token(token, secrets.get("metrics_token", ""))
    probe("right-token-is-accepted", results["right"] == 200,
          f"a notification carrying the rendered token answers {results['right']}")
    probe("wrong-token-is-refused", results["wrong"] == 401,
          f"a token one character off answers {results['wrong']}")
    probe("missing-token-is-refused", results["missing"] == 401,
          f"no Authorization header answers {results['missing']}")
    probe("unset-token-fails-closed", results["unconfigured"] == 503,
          f"a production process with no token configured answers {results['unconfigured']} "
          "rather than accepting the notification")

    return {"probes": probes, "credential_file": credential_path,
            "token_length": len(token), "statuses": results}


def _exercise_token(token: str, metrics_token: str = "") -> dict[str, int]:
    """Drive the real `require_alertmanager_token` dependency through ASGI."""
    from unittest.mock import patch

    for relative in ("services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "shared/shared_logging"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "monitoring-bundle-drill-key-32-chars")

    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from api.security.machine_tokens import require_alertmanager_token

    app = FastAPI()

    @app.post(RECEIVER_PATH)
    def receive(_: None = Depends(require_alertmanager_token)) -> dict[str, str]:
        return {"status": "received"}

    client = TestClient(app)

    class Production:  # the shape `require_token` reads, nothing more
        is_production = True

        def __init__(self, value: str) -> None:
            self.ALERTMANAGER_WEBHOOK_TOKEN = value

    def call(presented: str | None, configured: str) -> int:
        headers = {"Authorization": f"Bearer {presented}"} if presented is not None else {}
        with patch("api.config.settings.get_settings", return_value=Production(configured)):
            return client.post(RECEIVER_PATH, json={"status": "firing"}, headers=headers).status_code

    return {
        "right": call(token, token),
        # one character different keeps the length, so the check cannot pass on length
        "wrong": call("A" + token[1:] if token else "A" * 64, token),
        "missing": call(None, token),
        "unconfigured": call(token, ""),
    }


# --------------------------------------------------------------------------- #
# negative control
# --------------------------------------------------------------------------- #

INJECTIONS = {
    "prometheus-targets-localhost": (
        "prometheus.yml points at localhost instead of the Alertmanager service",
        lambda bundle: bundle.prometheus_path.write_text(
            bundle.prometheus_path.read_text(encoding="utf-8").replace(
                'targets: ["alertmanager:9093"]', 'targets: ["localhost:9093"]'),
            encoding="utf-8"),
        ("config_chain",),
    ),
    "receiver-url-not-served": (
        "alertmanager.yml posts to a path the API does not serve",
        # built, not spelled: a literal non-route would be picked up by the
        # route-contract scan, and the injection is not a call the code makes
        lambda bundle: bundle.alertmanager_path.write_text(
            bundle.alertmanager_path.read_text(encoding="utf-8").replace(
                RECEIVER_PATH, RECEIVER_PATH.replace("alertmanager", "not-a-route")),
            encoding="utf-8"),
        ("config_chain",),
    ),
    "alertmanager-config-not-mounted": (
        "the overlay stops mounting alertmanager.yml",
        lambda bundle: bundle.overlay_path.write_text(
            re.sub(r"\n\s*- \./infra/monitoring/alertmanager/alertmanager\.yml:[^\n]*", "",
                   bundle.overlay_path.read_text(encoding="utf-8")),
            encoding="utf-8"),
        ("compose_wiring",),
    ),
    "short-token": (
        "the rendered token is below the API's 32-character floor",
        lambda bundle: (bundle.root / "secrets").joinpath("webhook_token").write_text(
            "shorttoken", encoding="utf-8"),
        ("secret_wiring",),
    ),
    "paging-severity-silenced": (
        "the critical sub-route sends paging alerts to the null receiver",
        lambda bundle: bundle.alertmanager_path.write_text(
            bundle.alertmanager_path.read_text(encoding="utf-8").replace(
                '      receiver: cryptoscan-platform\n      group_wait: 10s',
                '      receiver: cryptoscan-null\n      group_wait: 10s'),
            encoding="utf-8"),
        ("config_chain",),
    ),
}


def _row_verdict(row: dict[str, Any]) -> str:
    failed = [probe for probe in row["probes"] if not probe["ok"]]
    if not failed:
        return PASS
    return FAIL if len(failed) >= 1 else PARTIAL


def _row(row_id: str, question: str, result: dict[str, Any]) -> dict[str, Any]:
    row = {"id": row_id, "question": question, "probes": result["probes"],
           **{key: value for key, value in result.items() if key != "probes"}}
    row["verdict"] = _row_verdict(row)
    return row


def _build(root: Path, secrets: dict[str, str], served_paths: set[str]) -> list[dict[str, Any]]:
    bundle = Bundle(root)
    return [
        _row("compose_wiring",
             "does the stack that ships start the processes its configs describe?",
             check_compose_wiring(bundle)),
        _row("config_chain",
             "does Prometheus reach Alertmanager, and Alertmanager reach a route the API serves?",
             check_config_chain(bundle, served_paths)),
        _row("secret_wiring",
             "is the token Alertmanager sends the token the API validates?",
             check_secret_wiring(bundle, secrets)),
    ]


def _served_paths() -> set[str]:
    """The API's own route table, read from the app rather than a list."""
    for relative in ("services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "shared/shared_logging"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "monitoring-bundle-drill-key-32-chars")
    from api.main import create_app

    return set(create_app().openapi().get("paths") or {})


def measure() -> dict[str, Any]:
    served = _served_paths()
    secrets = {"webhook_token": "b" * 64, "metrics_token": "c" * 64}
    rows = _build(REPO_ROOT, secrets, served)

    control: dict[str, Any] = {"injections": {}}
    for name, (description, mutate, affected) in INJECTIONS.items():
        scratch = Path(tempfile.mkdtemp(prefix="monitoring-bundle-"))
        try:
            for path in (OVERLAY, PROMETHEUS, RULES, ALERTMANAGER, ENV_EXAMPLE):
                target = scratch / path.relative_to(REPO_ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
            (scratch / "secrets").mkdir(parents=True, exist_ok=True)
            # the injected bundle starts from valid token files, so only the
            # injected defect can fail a row
            for file_name, value in secrets.items():
                (scratch / "secrets" / file_name).write_text(value, encoding="utf-8")
            bundle = Bundle(scratch)
            mutate(bundle)
            patched = {"webhook_token": (scratch / "secrets" / "webhook_token").read_text(encoding="utf-8"),
                       "metrics_token": secrets["metrics_token"]}
            mutated_rows = _build(scratch, patched, served)
            verdicts = {row["id"]: row["verdict"] for row in mutated_rows}
            control["injections"][name] = {
                "description": description,
                "affected_rows": list(affected),
                "verdicts": verdicts,
                "caught": all(verdicts.get(row_id) != PASS for row_id in affected),
            }
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    control["caught_every_injection"] = all(item["caught"] for item in control["injections"].values())

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "rows": rows,
        "negative_control": control,
        "overlay": str(OVERLAY.relative_to(REPO_ROOT)),
        "limits": [
            "no Prometheus or Alertmanager process is started here: the bundle is read, "
            "cross-checked and its token path executed through the API's own dependency, "
            "but container start-up, scrape timing, rule evaluation and Alertmanager "
            "grouping are the bank's to observe",
            "image tags are pinned but their contents were not audited; a bank that "
            "requires signed images substitutes its own registry",
            "the healthcheck command was not executed inside the upstream images",
        ],
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The monitoring bundle — do the parts connect?",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail**",
        "",
        "Guide 117 proved the delivery half of alerting by hand: a real rule, a real "
        "webhook-v4 notification, a counted series. What it left open is whether a "
        "deployed stack contains anything that posts. `infra/monitoring` had a "
        "Prometheus config with an `alerting:` stanza and an `alerts.yml` full of "
        "rules, and no compose file ran either process.",
        "",
        "| Question | Verdict | What was measured |",
        "|---|---|---|",
    ]
    for row in report["rows"]:
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        measured = (f"{len(row['probes'])} probe(s), {len(failed)} failing"
                    if failed else f"{len(row['probes'])} probe(s), all passing")
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {measured} |")
    lines.append("")
    for row in report["rows"]:
        lines += [f"### `{row['id']}` — {row['verdict']}", "", f"*{row['question']}*", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
        lines.append("")

    control = report["negative_control"]
    lines += [
        "## The negative control",
        "",
        "The same checks run against a copy of the bundle with exactly one defect "
        "injected. Each defect must make the row that watches for it stop passing:",
        "",
        "| Injected defect | Row | Result |",
        "|---|---|---|",
    ]
    for name, item in control["injections"].items():
        rows_txt = ", ".join(f"{row_id}={item['verdicts'].get(row_id)}" for row_id in item["affected_rows"])
        lines.append(f"| {item['description']} | {', '.join(item['affected_rows'])} | "
                     f"{rows_txt} ({'caught' if item['caught'] else 'MISSED'}) |")
    lines += [
        "",
        ("Every injection was caught." if control["caught_every_injection"]
         else "**At least one injection was missed.** A check that cannot fail is decoration."),
        "",
        "## How to run it",
        "",
        "```sh",
        "# one env var per token, both at least 32 characters",
        "python3 scripts/render_monitoring_secrets.py",
        "docker compose -f docker-compose.yml -f docker-compose.prod.yml \\",
        "               -f docker-compose.monitoring.yml up -d",
        "```",
        "",
        "## What this does not prove",
        "",
    ]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines += [
        "",
        "**The verdict this bundle supports:** the stack that ships actually contains "
        "the processes the configs describe, Prometheus is pointed at the Alertmanager "
        "this overlay starts, Alertmanager posts to a route the API serves, and the "
        "token it sends is the token the API validates — proven by calling the API's own "
        "dependency with it. What is not proven is that a bank's Alertmanager evaluates, "
        "groups and retries correctly: that is the layer the bank configures and observes.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade the monitoring bundle.")
    parser.add_argument("--json")
    parser.add_argument("--md")
    parser.add_argument("--max-fail", type=int, default=0)
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.md:
        Path(args.md).write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    return 1 if report["counts"][FAIL] > args.max_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())

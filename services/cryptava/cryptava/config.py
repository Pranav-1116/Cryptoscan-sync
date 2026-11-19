"""Agent configuration and on-disk state.

Two files, kept apart on purpose:

* **config** (``/etc/cryptava/cryptava.toml`` or ``.json``) — written by the bank's
  deployment tooling, readable by operators, contains no secrets;
* **state** (``/var/lib/cryptava/``, mode 0700) — written by ``cryptava enroll``:
  ``identity.json`` (agent id, name, API key — 0600) and ``agent.key`` (the agent's
  Ed25519 private key — 0600). Neither is ever printed or sent anywhere except the API
  key in the ``X-API-Key`` header to the configured console.

Every config key may be overridden by an environment variable ``CRYPTAVA_<KEY>``
(upper-case), which is how the Kubernetes DaemonSet and the container image set them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover — 3.9/3.10
    tomllib = None  # type: ignore[assignment]

DEFAULT_CONFIG_PATHS = ["/etc/cryptava/cryptava.toml", "/etc/cryptava/cryptava.json"]
DEFAULT_STATE_DIR = "/var/lib/cryptava"

DEFAULTS: dict[str, Any] = {
    "server": None,                 # https://cryptoscan.bank.example — the console URL
    "ca_file": None,                # CA bundle that signs the console's TLS certificate
    "insecure_skip_verify": False,  # never in production
    "estate": "default",
    "scope": None,
    "root": "/",                    # /host in a DaemonSet, /proc/1/root as a sidecar
    "proc": "/proc",
    "sys": "/sys",
    "interval": 3600,               # seconds between full collections
    "heartbeat_interval": 60,
    "jitter": 120,                  # random 0..jitter seconds so a fleet does not stampede
    "timeout": 60,                  # HTTP timeout
    "tags": {},                     # {"environment": "prod", "datacenter": "dc1", "owner": "..."}
    "system": None,                 # optional approved business-system mapping (TechBOM)
    "probe_listeners": True,
    "probe_exclude_ports": [],
    "probe_timeout": 2.5,
    "max_probes": 64,
    "cert_dirs": [],
    "jar_dirs": None,
    "python_packages": True,
    "java_archives": True,
    "max_packages": 6000,
    "max_certificates": 500,
    "dmidecode": True,
    "asset_record": None,           # CMDB/procurement record (default /etc/cryptava/asset-record.json)
    "hardware": None,               # inline hardware record (overrides the file's "hardware")
    "contracts": None,              # inline vendor contracts (overrides the file's "contracts")
    "performance_interval": 60,     # seconds between live performance samples (0 = off)
    "performance_scope": "auto",    # auto | host (whole machine) | workload (a sidecar's server)
    "hsm_probe": None,              # "127.0.0.1:8443" — time an HSM's response (crypto.hsm_operation_latency_ms)
}

_BOOL = {"insecure_skip_verify", "probe_listeners", "python_packages", "java_archives", "dmidecode"}
_INT = {"interval", "heartbeat_interval", "performance_interval", "jitter", "timeout", "max_probes", "max_packages", "max_certificates"}
_FLOAT = {"probe_timeout"}
_JSON = {"tags", "system", "probe_exclude_ports", "cert_dirs", "jar_dirs", "hardware", "contracts"}


class ConfigError(ValueError):
    pass


def _read(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix == ".toml":
        if tomllib is None:
            raise ConfigError(f"{path}: TOML needs Python 3.11+; use cryptava.json instead")
        data = tomllib.loads(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: the configuration must be a table/object")
    return data


def load_config(path: str | None = None, *, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    config = json.loads(json.dumps(DEFAULTS))
    chosen = path or env.get("CRYPTAVA_CONFIG")
    candidates = [chosen] if chosen else DEFAULT_CONFIG_PATHS
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            config.update(_read(Path(candidate)))
            config["_config_path"] = candidate
            break
    else:
        if chosen:
            raise ConfigError(f"config file {chosen} not found")
    for key in list(DEFAULTS) + ["name", "hostname", "domain", "fqdn", "primary_ip", "state_dir"]:
        raw = env.get(f"CRYPTAVA_{key.upper()}")
        if raw is None or raw == "":
            continue
        try:
            if key in _BOOL:
                config[key] = raw.strip().lower() in {"1", "true", "yes", "on"}
            elif key in _INT:
                config[key] = int(raw)
            elif key in _FLOAT:
                config[key] = float(raw)
            elif key in _JSON:
                config[key] = json.loads(raw)
            else:
                config[key] = raw
        except ValueError as exc:
            raise ConfigError(f"CRYPTAVA_{key.upper()}={raw!r}: {exc}") from exc
    if config.get("server"):
        config["server"] = str(config["server"]).rstrip("/")
    if not isinstance(config.get("tags"), dict):
        raise ConfigError("tags must be a table/object")
    return config


class State:
    """``identity.json`` + ``agent.key`` under the state directory."""

    def __init__(self, directory: str | os.PathLike) -> None:
        self.dir = Path(directory)

    @property
    def identity_path(self) -> Path:
        return self.dir / "identity.json"

    @property
    def key_path(self) -> Path:
        return self.dir / "agent.key"

    @property
    def spool_path(self) -> Path:
        return self.dir / "pending-observation.json"

    @property
    def last_run_path(self) -> Path:
        return self.dir / "last-run.json"

    @property
    def last_performance_path(self) -> Path:
        return self.dir / "last-performance.json"

    def ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def identity(self) -> dict[str, Any] | None:
        try:
            return json.loads(self.identity_path.read_text())
        except (OSError, ValueError):
            return None

    def save_identity(self, identity: dict[str, Any]) -> None:
        self.ensure()
        write_private(self.identity_path, json.dumps(identity, indent=2, sort_keys=True) + "\n")

    def write_json(self, path: Path, data: Any, *, private: bool = False) -> None:
        self.ensure()
        text = json.dumps(data, indent=2, sort_keys=True, default=str) + "\n"
        if private:
            write_private(path, text)
        else:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(text)
            os.replace(tmp, path)


def write_private(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    os.replace(tmp, path)
    os.chmod(path, 0o600)

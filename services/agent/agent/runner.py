"""The bank-side agent: a transport for collectors, never a scanner.

The architecture splits three jobs and this module is only the middle one:

* **collectors observe.** They are separate programs on the bank's hosts, platform
  controllers and network sensors; each writes one normalised observation file per plane.
  Nothing here reads a host, opens a socket, or executes anything;
* **the agent moves what they wrote.** It merges the plane files into one observation,
  hashes it, and posts it to the control plane — and when the hash has not moved since the
  last accepted push it posts *nothing at all*, because an agent that uploads an unchanged
  estate on a timer is the thing this architecture exists to avoid;
* **the platform decides.** The agent has no opinion about risk, no local verdict and no
  authority to mark a plane healthy: it reports what the collectors said, including the
  planes that said nothing.

Four rules the implementation keeps, each because the alternative is a lie an operator
would act on:

1. **a collector that failed is reported as FAILED**, with its reason, and its plane is
   never silently dropped — an empty directory must never look like an estate with no
   crypto;
2. **an empty observation is not pushed.** With no assets and no evidence there is nothing
   to say, and a push would advance the twin's "last observed" clock on no evidence;
3. **the last-hash cache is only advanced on success.** A failed push keeps the old hash so
   the next cycle retries instead of silently swallowing the change;
4. **a rejected credential is not retried.** 401/403 stops the cycle; retrying a bad token
   is how an account gets locked out at 03:00.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

SCHEMA = "cryptoscan.agent/1"

OBSERVATIONS_PATH = "/api/v1/ingestion/observations"

#: states one agent cycle can end in. ``UNCHANGED`` means the agent did not post at all.
PUSHED = "PUSHED"
UNCHANGED = "UNCHANGED"
NOTHING_COLLECTED = "NOTHING_COLLECTED"
REFUSED = "REFUSED"
FAILED = "FAILED"

#: 4xx that will not improve by trying again
TERMINAL_STATUSES = {400, 401, 403, 404, 409, 413, 422}

LIMITS = [
    "the agent never scans: it transports what collectors wrote and reports their outcomes",
    "an unchanged observation is not posted, so the control plane learns nothing about a "
    "healthy estate from this process — liveness is the heartbeat the platform writes when "
    "it does receive one",
    "the state hash is computed over the observation the agent sends; a collector that "
    "changes its normalisation changes the hash without changing the estate",
    "retries cover transport and 5xx failures only; a rejected credential stops the cycle",
    "no key material is stored here beyond the path to the signing key",
]


def state_hash(observation: Mapping[str, Any]) -> str:
    """The agent's own hash of the normalised observation (canonical JSON, sorted keys)."""
    material = {
        "assets": sorted(json.dumps(item, sort_keys=True, default=str) for item in observation.get("assets") or []),
        "evidence": sorted(json.dumps(item, sort_keys=True, default=str) for item in observation.get("evidence") or []),
        "relationships": sorted(
            json.dumps(item, sort_keys=True, default=str) for item in observation.get("relationships") or []
        ),
        "coverage": sorted(
            json.dumps(item, sort_keys=True, default=str) for item in observation.get("coverage") or []
        ),
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()


def signed_view(document: Mapping[str, Any]) -> dict[str, Any]:
    """The exact document the platform verifies (``ingestion.signed_document``).

    The platform does not verify the posted body as-is: it rebuilds the observation from
    its known fields (with their defaults) and checks the signature over that. Signing
    anything else — e.g. the body with ``state_hash`` — reports ``INVALID``.
    """
    view: dict[str, Any] = {
        "schema": "cryptoscan.live-observation/1",
        "estate": document.get("estate") or "default",
        "scope": document.get("scope"),
        "inventory_id": document.get("inventory_id") or "default",
        "observed_at": document.get("observed_at"),
    }
    for name in ("assets", "evidence", "relationships", "collectors", "coverage"):
        view[name] = list(document.get(name) or [])
    if document.get("contributor"):
        view["contributor"] = document["contributor"]
    return view


class DirectorySource:
    """Merge per-plane observation files a collector set has written to one directory.

    The file contract is deliberately small: a JSON object with ``assets``, ``evidence``
    and optional ``relationships``/``coverage``/``estate``/``scope``. The file name and
    the ``plane`` field identify the collector's plane.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def files(self) -> list[Path]:
        if not self.directory.exists():
            return []
        return sorted(path for path in self.directory.glob("*.json") if path.is_file())

    def collect(self) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        collectors: list[dict[str, Any]] = []
        coverage: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        estate: str | None = None
        scope: str | None = None

        for path in self.files():
            plane = path.stem
            try:
                parsed = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                failures.append(
                    {"plane": plane, "source_file": str(path), "reason": f"{type(exc).__name__}: {exc}"}
                )
                collectors.append(
                    {
                        "plane": plane,
                        "state": "FAILED",
                        "expected": 1,
                        "collected": 0,
                        "reason": f"the collector file could not be read: {exc}",
                    }
                )
                coverage.append(
                    {"plane": plane, "expected": 1, "collected": 0,
                     "reason": "collector output unreadable, so this plane is NOT_OBSERVED"}
                )
                continue
            if not isinstance(parsed, dict):
                failures.append({"plane": plane, "source_file": str(path), "reason": "not a JSON object"})
                collectors.append(
                    {"plane": plane, "state": "FAILED", "expected": 1, "collected": 0,
                     "reason": "the collector file is not a JSON object"}
                )
                coverage.append(
                    {"plane": plane, "expected": 1, "collected": 0,
                     "reason": "collector output malformed, so this plane is NOT_OBSERVED"}
                )
                continue

            plane_name = str(parsed.get("plane") or plane)
            observations.append(parsed)
            estate = estate or (str(parsed["estate"]) if parsed.get("estate") else None)
            scope = scope or (str(parsed["scope"]) if parsed.get("scope") else None)

            stated = parsed.get("coverage")
            if isinstance(stated, Mapping):
                row = {key: value for key, value in stated.items() if key != "plane"}
            elif isinstance(stated, list) and stated:
                row = dict(stated[0])
            else:
                row = {
                    "expected": None,
                    "collected": None,
                    "reason": "the collector file stated no coverage, so this plane's completeness is UNKNOWN",
                }
            coverage.append({"plane": plane_name, **row})
            collectors.append(
                {
                    "plane": plane_name,
                    "state": str(parsed.get("state") or ("COMPLETE" if row.get("expected") else "PARTIAL")),
                    "expected": row.get("expected"),
                    "collected": row.get("collected"),
                    "reason": row.get("reason"),
                }
            )

        merged: dict[str, Any] = {
            "estate": estate or "default",
            "scope": scope,
            "assets": [item for parsed in observations for item in (parsed.get("assets") or [])],
            "evidence": [item for parsed in observations for item in (parsed.get("evidence") or [])],
            "relationships": [item for parsed in observations for item in (parsed.get("relationships") or [])],
            "collectors": collectors,
            "coverage": coverage,
        }
        if failures:
            # stated, not hidden: the observation carries the planes that could not be read,
            # so the platform stores FAILED rather than an estate that looks smaller
            merged["failures"] = failures
        return merged


def _default_transport(url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> tuple[int, Any]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 — explicit origin
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        payload = exc.read() or b"{}"
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = {"detail": payload.decode("utf-8", "replace")}
        return exc.code, parsed
    except urllib.error.URLError as exc:
        return 0, {"detail": f"cannot reach the control plane: {exc.reason}"}


@dataclass
class AgentConfig:
    server: str
    token: str | None = None
    interval_seconds: int = 300
    source_dir: str | Path = "."
    sign_key: str | None = None
    state_path: Path | None = None
    estate: str | None = None
    scope: str | None = None
    timeout_seconds: float = 20.0
    retries: int = 2
    backoff_seconds: float = 2.0
    tenant_id: str | None = None


@dataclass
class Agent:
    config: AgentConfig
    source: Any = None
    transport: Callable[..., tuple[int, Any]] = _default_transport
    _last_hash: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.source is None:
            self.source = DirectorySource(self.config.source_dir)
        if self._last_hash is None and self.config.state_path is not None:
            try:
                stored = json.loads(Path(self.config.state_path).read_text())
                self._last_hash = str(stored.get("last_hash") or "") or None
            except (OSError, ValueError):
                self._last_hash = None

    # -- helpers ------------------------------------------------------------- #
    def _remember(self, digest: str) -> None:
        self._last_hash = digest
        if self.config.state_path is None:
            return
        try:
            Path(self.config.state_path).parent.mkdir(parents=True, exist_ok=True)
            Path(self.config.state_path).write_text(json.dumps({"schema": SCHEMA, "last_hash": digest}))
        except OSError:
            # a cache that cannot be written costs bandwidth, never correctness
            pass

    def _post(self, observation: Mapping[str, Any], digest: str) -> tuple[int, Any]:
        document = dict(observation)
        document["state_hash"] = digest
        if self.config.estate:
            document["estate"] = self.config.estate
        if self.config.scope:
            document["scope"] = self.config.scope
        if self.config.sign_key:
            from shared_models import release_signature

            key = release_signature.load_private_key(self.config.sign_key)
            document["signature"] = release_signature.sign_document(signed_view(document), key)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        if self.config.tenant_id:
            headers["X-Tenant-ID"] = self.config.tenant_id
        url = self.config.server.rstrip("/") + OBSERVATIONS_PATH
        payload = json.dumps(document, default=str).encode("utf-8")
        return self.transport(url, headers, payload, self.config.timeout_seconds)

    # -- one cycle ----------------------------------------------------------- #
    def run_once(self) -> dict[str, Any]:
        """Collect, hash, and post only if the estate moved. Never raises."""
        observation = self.source.collect()
        collectors = list(observation.get("collectors") or [])
        assets = list(observation.get("assets") or [])
        evidence = list(observation.get("evidence") or [])
        digest = state_hash(observation)
        base = {
            "schema": SCHEMA,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "state_hash": digest,
            "collectors": collectors,
            "planes_failed": [item.get("plane") for item in collectors if item.get("state") == "FAILED"],
            "assets": len(assets),
            "evidence": len(evidence),
        }

        if not assets and not evidence:
            return {
                **base,
                "state": NOTHING_COLLECTED,
                "posted": False,
                "reason": (
                    "no collector produced any asset or evidence; pushing an empty observation would "
                    "advance the estate's observation clock on no evidence"
                ),
            }

        if self._last_hash == digest:
            return {
                **base,
                "state": UNCHANGED,
                "posted": False,
                "reason": "the observation hashes to the last accepted push, so nothing was sent",
            }

        attempt = 0
        last: tuple[int, Any] = (0, {"detail": "not attempted"})
        while attempt <= max(0, self.config.retries):
            status, payload = self._post(observation, digest)
            last = (status, payload)
            answer = payload if isinstance(payload, Mapping) else {}
            if status and status not in TERMINAL_STATUSES and status < 500:
                self._remember(digest)
                return {
                    **base,
                    "state": PUSHED,
                    "posted": True,
                    "status": status,
                    "server_state": answer.get("state"),
                    "stored": answer.get("stored"),
                    "projection_id": answer.get("projection_id"),
                    "reason": "the control plane accepted the observation",
                }
            if status in TERMINAL_STATUSES:
                return {
                    **base,
                    "state": REFUSED,
                    "posted": True,
                    "status": status,
                    "reason": f"the control plane refused this observation (HTTP {status})",
                    "detail": payload,
                    "note": (
                        "a refused observation is not retried: retrying a rejected credential at "
                        "03:00 is how an account gets locked out"
                    ),
                }
            attempt += 1
            if attempt <= max(0, self.config.retries):
                time.sleep(self.config.backoff_seconds * attempt)

        return {
            **base,
            "state": FAILED,
            "posted": True,
            "status": last[0],
            "reason": (
                "the control plane did not accept this observation after retries; the last-hash "
                "cache was NOT advanced, so the next cycle retries the same change"
            ),
            "detail": last[1],
        }

    def run_forever(
        self, *, cycles: int | None = None, clock: Callable[[float], None] = time.sleep
    ) -> Iterable[dict[str, Any]]:
        """Yield one result per cycle. The caller decides what to do with a failure."""
        done = 0
        while cycles is None or done < cycles:
            yield self.run_once()
            done += 1
            if cycles is not None and done >= cycles:
                break
            clock(self.config.interval_seconds)


def main(argv: list[str] | None = None) -> int:
    """``python -m agent.runner`` — a long-running transport, not a scanner."""
    import argparse
    import os

    parser = argparse.ArgumentParser(prog="cryptoscan-agent", description=__doc__)
    parser.add_argument("--source", default=os.getenv("CRYPTOSCAN_AGENT_SOURCE", "."),
                        help="directory of per-plane observation files written by collectors")
    parser.add_argument("--server", default=os.getenv("CRYPTOSCAN_SERVER", ""),
                        help="control plane origin (https in a bank)")
    parser.add_argument("--token", default=os.getenv("CRYPTOSCAN_TOKEN"),
                        help="short-lived session token (never a permanent API key)")
    parser.add_argument("--sign-key", dest="sign_key", default=os.getenv("CRYPTOSCAN_AGENT_KEY"),
                        help="Ed25519 private key (PEM) used to sign each observation")
    parser.add_argument("--state", default=os.getenv("CRYPTOSCAN_AGENT_STATE", ""),
                        help="where to remember the last pushed state hash")
    parser.add_argument("--interval", type=int, default=int(os.getenv("CRYPTOSCAN_AGENT_INTERVAL", "300")))
    parser.add_argument("--estate", default=None)
    parser.add_argument("--scope", default=None)
    parser.add_argument("--tenant", default=os.getenv("CRYPTOSCAN_TENANT_ID"))
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--json", action="store_true", help="machine-readable result per cycle")
    args = parser.parse_args(argv)

    if not args.server:
        print("agent: REFUSED — no control plane configured (--server or CRYPTOSCAN_SERVER)")
        return 3

    agent = Agent(
        AgentConfig(
            server=args.server,
            token=args.token,
            interval_seconds=max(30, args.interval),
            source_dir=args.source,
            sign_key=args.sign_key or None,
            state_path=Path(args.state) if args.state else None,
            estate=args.estate,
            scope=args.scope,
            tenant_id=args.tenant,
        )
    )
    exit_code = 0
    for result in agent.run_forever(cycles=1 if args.once else None):
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            failed = ",".join(result.get("planes_failed") or []) or "none"
            print(
                f"{result['state']:<18} assets {result['assets']:<6} evidence {result['evidence']:<6} "
                f"failed planes {failed}"
            )
            print(f"  {result['reason']}")
            print(f"  state hash {result['state_hash'][:16]}…")
        if result["state"] in {REFUSED, FAILED}:
            exit_code = 2
        if args.once:
            break
    return exit_code


if __name__ == "__main__":  # pragma: no cover — the entry point itself
    raise SystemExit(main())

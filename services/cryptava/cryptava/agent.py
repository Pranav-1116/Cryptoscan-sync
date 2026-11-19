"""One Cryptava cycle: read the host → build the observation → sign → send → heartbeat."""

from __future__ import annotations

import platform
import socket
import time
from pathlib import Path
from typing import Any

from cryptava import __version__
from cryptava.collectors import Context, collect_all
from cryptava.config import State
from cryptava.observation import state_hash
from cryptava.signing import SigningKey
from cryptava.transport import Client, TransportError
from cryptava.util import HostView


def host_view(config: dict[str, Any]) -> HostView:
    return HostView(root=Path(config.get("root") or "/"), proc=Path(config.get("proc") or "/proc"),
                    sys=Path(config.get("sys") or "/sys"))


def collect(config: dict[str, Any]) -> Context:
    ctx = Context(view=host_view(config), config=config)
    started = time.monotonic()
    collect_all(ctx)
    ctx.notes.append(f"collection took {time.monotonic() - started:.1f}s")
    return ctx


def build_payload(ctx: Context, config: dict[str, Any], *, contributor: str | None,
                  key: SigningKey | None) -> dict[str, Any]:
    payload = ctx.obs.payload(estate=config.get("estate") or "default", scope=config.get("scope"),
                              contributor=contributor)
    payload["state_hash"] = state_hash(payload)
    if key is not None:
        payload["signature"] = key.signature_block(payload)
    return payload


def client_for(config: dict[str, Any], identity: dict[str, Any] | None) -> Client:
    return Client(config.get("server") or (identity or {}).get("server") or "",
                  api_key=(identity or {}).get("api_key"), ca_file=config.get("ca_file"),
                  insecure=bool(config.get("insecure_skip_verify")), timeout=float(config.get("timeout") or 60))


def summarise(ctx: Context, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "observed_at": payload["observed_at"],
        "contributor": payload.get("contributor"),
        "host": ctx.fqdn,
        "state_hash": payload["state_hash"],
        "signed": "signature" in payload,
        "counts": ctx.obs.counts(),
        "planes": [{"plane": p["plane"], "status": p["status"], "reason": p["reason"]}
                   for p in ctx.obs.planes.values()],
        "notes": ctx.notes,
    }


def enroll(config: dict[str, Any], state: State, *, agent_id: str | None, token: str | None,
           name: str | None = None, provision_key: str | None = None) -> dict[str, Any]:
    """Activate this host as a Cryptava agent and store its identity.

    Either ``agent_id`` + ``token`` from the console's *Enrol agent* step, or — for
    automated rollouts — a provisioning key with admin rights plus a ``name``: the agent
    is then enrolled and activated in one go. The provisioning key is used for these two
    calls only and never stored.
    """
    client = client_for(config, None)
    if not (agent_id and token):
        if not (provision_key and name):
            raise TransportError("enrol needs --agent-id and --token from the console "
                                 "(or --name with a provisioning key)")
        # an admin API key goes in X-API-Key; "Bearer <session token>" in Authorization
        auth: dict[str, Any] = ({"headers": {"Authorization": provision_key}}
                                if provision_key.lower().startswith("bearer ") else {"api_key": provision_key})
        try:
            enrolled = client.post("/api/v1/control/agents/enroll",
                                   {"name": name, "environment": (config.get("tags") or {}).get("environment"),
                                    "region": (config.get("tags") or {}).get("datacenter"), "platform": "linux"},
                                   **auth)
        except TransportError as exc:
            detail = (exc.body or {}).get("detail") if isinstance(exc.body, dict) else None
            existing = detail.get("existing_agent_id") if isinstance(detail, dict) else None
            if exc.status != 409 or not existing:
                raise
            # the name is already enrolled: a rebuilt host keeps its name and gets a new token
            enrolled = client.post(f"/api/v1/control/agents/{existing}/enrollment-token", {}, **auth)
        agent_id, token = enrolled["agent_id"], enrolled["enrollment_token"]
    state.ensure()
    key = SigningKey.generate()
    response = client.post("/api/v1/control/agents/activate", {
        "agent_id": agent_id, "enrollment_token": token, "public_key": key.public_b64,
        "hostname": config.get("fqdn") or socket.getfqdn(), "platform": f"{platform.system().lower()}",
        "version": __version__,
    })
    key.save(state.key_path)
    identity = {
        "agent_id": response["agent_id"], "name": response["name"], "contributor": response.get("contributor"),
        "api_key": response["api_key"], "key_id": response["key_id"], "server": client.server,
        "observations_path": response.get("observations_path", "/api/v1/ingestion/observations"),
        "heartbeat_path": response.get("heartbeat_path", "/api/v1/control/agents/heartbeat"),
        "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    state.save_identity(identity)
    return {k: v for k, v in identity.items() if k != "api_key"}


def heartbeat(client: Client, identity: dict[str, Any], *, healthy: bool, buffered: int) -> dict[str, Any]:
    return client.post(identity.get("heartbeat_path") or "/api/v1/control/agents/heartbeat", {
        "agent_id": identity["agent_id"], "version": __version__, "healthy": healthy,
        "link": "encrypted" if client.server.startswith("https://") else "plaintext",
        "offline_events_buffered": buffered,
    })


def run_once(config: dict[str, Any], state: State, *, send: bool = True) -> dict[str, Any]:
    identity = state.identity()
    if send and not identity:
        raise TransportError("this host is not enrolled yet — run `cryptava enroll` first")
    key = SigningKey.load(state.key_path) if identity and state.key_path.exists() else None
    contributor = (identity or {}).get("contributor") or (identity or {}).get("name") or config.get("name")
    ctx = collect(config)
    payload = build_payload(ctx, config, contributor=contributor, key=key)
    summary = summarise(ctx, payload)
    if not send:
        return {"summary": summary, "payload": payload}

    client = client_for(config, identity)
    result: dict[str, Any] = {"summary": summary}
    # a previous cycle that could not be delivered is superseded — each observation is the
    # agent's whole slice, so only the newest one matters
    try:
        response = client.post(identity.get("observations_path") or "/api/v1/ingestion/observations",
                               {**payload, "include_boms": False})
        if state.spool_path.exists():
            state.spool_path.unlink()
        result["delivered"] = True
        authenticity = response.get("authenticity") or {}
        result["response"] = {
            "state": response.get("state"),
            "stored": response.get("stored"),
            "run_id": response.get("run_id"),
            "authenticity": authenticity.get("status"),
            "signed_by_agent": authenticity.get("signed_by_agent"),
            "contribution": response.get("contribution"),
            "counts": response.get("counts"),
            "bom_counts": response.get("bom_counts"),
            "warnings": response.get("warnings"),
        }
    except TransportError as exc:
        state.write_json(state.spool_path, payload, private=True)
        result["delivered"] = False
        result["error"] = str(exc)
        result["status"] = exc.status
    try:
        heartbeat(client, identity, healthy=result["delivered"], buffered=0 if result["delivered"] else 1)
        result["heartbeat"] = "ok"
    except TransportError as exc:
        result["heartbeat"] = str(exc)
    state.write_json(state.last_run_path, result)
    return result


def send_performance(config: dict[str, Any], state: State, sampler: Any, *, send: bool = True) -> dict[str, Any]:
    """One live performance sample: read → sign → send (see ``cryptava.performance``).

    The result is written to ``last-performance.json`` so ``cryptava status --brief``
    and ``run_sandbox.sh agents check`` can say whether live metrics are flowing.
    """
    from cryptava import performance

    identity = state.identity() or {}
    key = SigningKey.load(state.key_path) if identity and state.key_path.exists() else None
    sample = sampler.sample()
    document = performance.signed_sample(sample, identity, config, key)
    if not send:
        return {"document": document}
    result: dict[str, Any] = {"observed_at": sample["observed_at"], "metrics": len(sample["metrics"]),
                              "scope": sample["scope"]}
    try:
        response = performance.send(client_for(config, identity), identity, document)
        result.update(delivered=True, accepted=response.get("accepted"), rejected=response.get("rejected"),
                      authenticity=response.get("authenticity"), asset_id=response.get("asset_id"))
    except TransportError as exc:
        result.update(delivered=False, error=str(exc), status=exc.status)
    state.write_json(state.last_performance_path, result)
    return result

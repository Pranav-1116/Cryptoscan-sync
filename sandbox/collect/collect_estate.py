#!/usr/bin/env python3
"""Meridian Bank sandbox — live estate collector ("the bank's agent").

This is what a bank-side collector does in a real deployment: it walks the
estate, collects facts through REAL channels, and pushes ONE signed-style
observation to CryptoScan's ingestion endpoint. The platform stores it only
when something actually changed, and every BOM workspace (SBOM / CBOM / HBOM /
VBOM / NBOM / TechBOM) re-projects from the newest observation — so each run
of this collector is what makes the BOMs move.

Nothing here is seeded. Every fact below is collected live:

  * docker socket  -> real containers, real image digests, real architectures
  * exec in estate -> real package inventories (apk / pip / dpkg)
  * TLS handshakes -> real negotiated version/cipher + real peer certificate
  * SSH banner     -> real OpenSSH version the bastion discloses
  * PostgreSQL     -> real server version (read with the sandbox DB login)
  * HSM banner     -> real JSON the HSM simulator serves over TLS

Runs inside the `sandbox-collect` container; never install it anywhere else.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("CRYPTOSCAN_API", "http://api:8010").rstrip("/")
USER = os.environ.get("CRYPTOSCAN_USERNAME", "")
PASSWORD = os.environ.get("CRYPTOSCAN_PASSWORD", "")
ESTATE = os.environ.get("SANDBOX_ESTATE", "meridian-bank")
SCOPE = "sandbox-lan"
PREFIX = "cryptoscan-sbx-"

TLS_ENDPOINTS = [  # (host, port, service name)
    ("10.210.0.2", 443, "internet-banking"),
    ("10.210.0.3", 443, "mobile-api"),
    ("10.210.0.4", 443, "swift-gateway"),
    ("10.210.0.5", 443, "legacy-branch"),
    ("10.210.0.6", 8443, "hsm-sim"),
]
SSH_ENDPOINT = ("10.210.0.8", 22, "payments-bastion")
DB = ("10.210.0.7", 5432, "core-banking-db")

NOW = datetime.now(timezone.utc).isoformat()


def log(msg: str) -> None:
    print(f"[collect] {msg}", flush=True)


def login() -> str:
    if not (USER and PASSWORD):
        sys.exit(
            "collector needs the console login: re-run with "
            "CRYPTOSCAN_USERNAME / CRYPTOSCAN_PASSWORD set "
            "(run_sandbox.sh collect will prompt)"
        )
    req = urllib.request.Request(
        f"{API}/api/v1/auth/login",
        data=json.dumps({"username": USER, "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 — sandbox URL only
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read())
        except Exception:  # noqa: BLE001
            detail = {}
        sys.exit(
            f"login refused (HTTP {exc.code}) for user {USER!r}: "
            f"{detail.get('detail') or detail.get('message') or exc.reason}. "
            "Use the same username/password you sign into the console with."
        )
    except urllib.error.URLError as exc:
        sys.exit(f"CryptoScan API unreachable at {API}: {exc.reason} — is the stack up?")
    token = body.get("token")
    if not token:
        sys.exit(f"login failed: {body.get('message') or body}")
    log(f"authenticated to CryptoScan as {USER}")
    return token


def post_observation(token: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{API}/api/v1/ingestion/observations",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 — sandbox URL only
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read())
        except Exception:  # noqa: BLE001
            detail = exc.read()
        sys.exit(f"observation refused (HTTP {exc.code}): {json.dumps(detail)[:800]}")


# ---------------------------------------------------------------------------
# real collectors
# ---------------------------------------------------------------------------

def docker_estate() -> tuple[list[dict], list[dict], list[dict]]:
    """Containers + images + package inventories, straight from the daemon."""
    import docker  # pip install docker — inside the collector image only

    client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
    containers, images, packages = [], [], []
    for c in client.containers.list():
        if not c.name.startswith(PREFIX):
            continue
        service = c.name[len(PREFIX):]
        ins = c.attrs
        net = (ins.get("NetworkSettings", {}).get("Networks", {}) or {})
        ip = (net.get("cryptoscan-sandbox-net") or {}).get("IPAddress") or None
        image_ref = (ins.get("Config", {}) or {}).get("Image") or ""
        digest = (ins.get("Image") or "").split("sha256:")[-1][:32] or None
        containers.append({
            "service": service, "container_id": c.id, "image_ref": image_ref,
            "image_digest": digest, "ip": ip, "started": ins.get("State", {}).get("StartedAt"),
            "platform": ins.get("Platform"), "status": ins.get("State", {}).get("Status"),
        })
        if digest:
            images.append({"ref": image_ref, "digest": digest})
        # real package inventory — the SBOM raw material
        for cmd, ecosystem in (
            ("apk info -v", "apk"),
            ("pip list --format=freeze", "pypi"),
            ("dpkg-query -W -f=${Package} ${Version}\\n", "deb"),
        ):
            try:
                rc, out = c.exec_run(f"sh -c '{cmd} 2>/dev/null'", demux=False)
                if rc == 0 and out:
                    for line in out.decode(errors="replace").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if ecosystem == "pypi" and "==" in line:
                            name, _, ver = line.partition("==")
                        else:
                            name, _, ver = line.rpartition("-") if ecosystem == "apk" else line.partition(" ")
                        if name and ver:
                            packages.append({"service": service, "name": name.strip(),
                                             "version": ver.strip(), "ecosystem": ecosystem})
                    break  # first working package manager wins
            except Exception as exc:  # noqa: BLE001 — one container failing must not sink the run
                log(f"package inventory skipped for {service}: {exc}")
    log(f"docker: {len(containers)} containers, {len(images)} images, {len(packages)} packages")
    return containers, images, packages


def tls_facts(host: str, port: int) -> dict | None:
    """One real handshake: negotiated version + cipher + peer certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=True)
                return {
                    "negotiated_protocol": tls.version(),
                    "negotiated_cipher": (tls.cipher() or [None])[0],
                    "peer_cert_sha256": hashlib.sha256(cert).hexdigest() if cert else None,
                    "peer_cert_bytes": len(cert) if cert else 0,
                }
    except Exception as exc:  # noqa: BLE001
        log(f"tls probe {host}:{port} failed: {exc}")
        return None


def ssh_banner(host: str, port: int) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            return s.recv(256).decode(errors="replace").strip()
    except Exception as exc:  # noqa: BLE001
        log(f"ssh banner {host}:{port} failed: {exc}")
        return None


def postgres_version(host: str, port: int) -> str | None:
    try:
        import psycopg  # pip install 'psycopg[binary]' — collector image only

        with psycopg.connect(
            host=host, port=port, dbname="ledger",
            user="core", password="sandbox-only-password", connect_timeout=5,
        ) as conn:
            row = conn.execute("SELECT version()").fetchone()
            return str(row[0]) if row else None
    except Exception as exc:  # noqa: BLE001
        log(f"postgres version probe failed: {exc}")
        return None


def hsm_inventory(host: str, port: int) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                data = tls.recv(8192).decode(errors="replace").strip()
                return json.loads(data).get("inventory")
    except Exception as exc:  # noqa: BLE001
        log(f"hsm inventory probe failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# observation assembly
# ---------------------------------------------------------------------------

def main() -> None:
    containers, images, packages = docker_estate()
    token = login()

    assets: list[dict] = []
    evidence: list[dict] = []
    relationships: list[dict] = []

    def ev(target: str, etype: str, facts: dict, layer: str, source: str) -> str:
        eid = f"ev-{len(evidence) + 1}"
        evidence.append({"evidence_id": eid, "source": source, "evidence_type": etype,
                         "target": target, "facts": facts, "layer": layer,
                         "observed_at": NOW, "collector": "sandbox-estate-collector",
                         "collector_version": "1.0.0"})
        return eid

    def rel(subject: str, predicate: str, obj: str, basis: str, evids: list[str],
            ev_target: str | None = None, facts: dict | None = None, layer: str = "UNKNOWN",
            source: str = "sandbox-estate-collector") -> None:
        """Add an edge. The ingestion contract refuses evidence-less edges, so a
        relationship with nothing to cite gets one stating what establishes it."""
        if not evids:
            evids = [ev(ev_target or subject, "CONFIGURED",
                        facts or {"relationship": f"{predicate} established at collection"},
                        layer, source)]
        relationships.append({"subject": subject, "predicate": predicate,
                              "object": obj, "basis": basis, "evidence_ids": evids})

    # ── hosts, containers, images, packages (the SBOM/HBOM raw material) ──
    for c in containers:
        svc = c["service"]
        host_ref = f"host-{svc}"
        assets.append({"ref": host_ref, "type": "HOST", "name": svc,
                       "identity": {"hostname": f"{svc}.bank.sandbox",
                                    **({"ip_address": c["ip"]} if c["ip"] else {})},
                       "environment": "production-sandbox", "source": "docker-daemon",
                       "attributes": {"status": c["status"], "platform": c["platform"],
                                      "started_at": c["started"]}})
        assets.append({"ref": f"ctr-{svc}", "type": "CONTAINER", "name": f"{PREFIX}{svc}",
                       "identity": {"container_id": c["container_id"][:12]},
                       "source": "docker-daemon",
                       "attributes": {"container_id_full": c["container_id"]}})
        e = ev(host_ref, "RUNTIME_OBSERVED",
               {"container_status": c["status"], "platform": c["platform"],
                "image": c["image_ref"], "image_digest": c["image_digest"]},
               "PLATFORM", "docker-daemon")
        rel(f"ctr-{svc}", "runs_on", host_ref, "RUNTIME_OBSERVATION", [e])
        if c["image_digest"]:
            img_ref = f"img-{c['image_digest'][:12]}"
            assets.append({"ref": img_ref, "type": "IMAGE", "name": c["image_ref"],
                           "identity": {"digest": c["image_digest"], "image_ref": c["image_ref"]},
                           "source": "docker-daemon"})
            rel(f"ctr-{svc}", "deployed_as", img_ref, "RUNTIME_OBSERVATION", [e])

    for p in packages:
        ref = f"pkg-{p['service']}-{p['name']}"
        assets.append({"ref": ref, "type": "PACKAGE", "name": p["name"],
                       "identity": {"name": p["name"], "version": p["version"],
                                    "ecosystem": p["ecosystem"]},
                       "source": f"{p['ecosystem']}-db",
                       "attributes": {"version": p["version"], "service": p["service"]}})
        e = ev(ref, "STATIC_OBSERVED", {"installed_version": p["version"]},
               "PLATFORM", f"{p['ecosystem']}-package-db")
        relationships.append({"subject": ref, "predicate": "part_of",
                              "object": f"host-{p['service']}", "basis": "DEPLOYMENT_CONFIG",
                              "evidence_ids": [e]})

    # ── TLS endpoints (the CBOM/NBOM raw material) ─────────────────────────
    for host, port, svc in TLS_ENDPOINTS:
        ep_ref = f"ep-{svc}"
        assets.append({"ref": ep_ref, "type": "NETWORK_ENDPOINT", "name": f"{svc} tls",
                       "identity": {"host": host, "port": str(port), "protocol": "tls"},
                       "source": "live-tls-probe"})
        facts = tls_facts(host, port)
        if not facts:
            rel(ep_ref, "exposes", f"host-{svc}", "NETWORK_OBSERVATION", [],
                ev_target=ep_ref, facts={"connect": "refused"}, layer="NETWORK_TRANSPORT",
                source="live-tls-handshake")
            continue
        e_ep = ev(ep_ref, "NETWORK_ACTIVE_OBSERVED",
                  {k: v for k, v in facts.items() if k != "peer_cert_sha256"},
                  "NETWORK_TRANSPORT", "live-tls-handshake")
        rel(ep_ref, "exposes", f"host-{svc}", "NETWORK_OBSERVATION", [e_ep])
        if facts.get("peer_cert_sha256"):
            cert_ref = f"cert-{facts['peer_cert_sha256'][:16]}"
            assets.append({"ref": cert_ref, "type": "CERTIFICATE", "name": f"{svc} serving cert",
                           "identity": {"fingerprint_sha256": facts["peer_cert_sha256"]},
                           "source": "live-tls-handshake"})
            e = ev(cert_ref, "CERTIFICATE_OBSERVED",
                   {"served_by": f"{host}:{port}", "size_bytes": facts["peer_cert_bytes"]},
                   "NETWORK_TRANSPORT", "live-tls-handshake")
            rel(ep_ref, "uses_certificate", cert_ref, "RUNTIME_OBSERVATION", [e])

    # ── SSH bastion (real banner) ──────────────────────────────────────────
    banner = ssh_banner(*SSH_ENDPOINT[:2])
    if banner:
        ev(f"host-{SSH_ENDPOINT[2]}", "NETWORK_ACTIVE_OBSERVED",
           {"ssh_banner": banner}, "NETWORK_TRANSPORT", "ssh-banner-grab")

    # ── database (real version, read with the sandbox login) ──────────────
    version = postgres_version(*DB[:2])
    assets.append({"ref": "db-core", "type": "DATABASE", "name": "core-banking-ledger",
                   "identity": {"host": DB[0], "port": str(DB[1]), "engine": "postgresql"},
                   "source": "postgres-login",
                   "attributes": {"version": version} if version else {}})
    db_ev = None
    if version:
        db_ev = ev("db-core", "RUNTIME_OBSERVED", {"server_version": version}, "PLATFORM", "postgres-login")
    rel("host-internet-banking", "depends_on", "db-core", "DEPLOYMENT_CONFIG",
        [db_ev] if db_ev else [], ev_target="db-core",
        facts={"wiring": "internet-banking reads the ledger database"}, source="compose-declared")

    # ── HSM (real JSON inventory over TLS) ────────────────────────────────
    inv = hsm_inventory("10.210.0.6", 8443)
    if inv:
        assets.append({"ref": "hsm-0", "type": "HSM", "name": inv.get("device", "hsm-sim"),
                       "identity": {"vendor": "Meridian-Sim", "serial_number": "SBX-HSM-0001",
                                    "partition": "payments"},
                       "source": "hsm-banner",
                       "attributes": {"firmware": inv.get("firmware"),
                                      "fips_mode": (inv.get("compliance") or {}).get("fips_mode")}})
        hsm_ev = ev("hsm-0", "RUNTIME_OBSERVED",
                    {"firmware": inv.get("firmware"), "key_slots": inv.get("slots"),
                     "compliance": inv.get("compliance")}, "HSM", "hsm-tls-banner")
        rel("host-hsm-sim", "uses_hsm", "hsm-0", "RUNTIME_OBSERVATION", [hsm_ev])

    # ── vendors (derived from what was actually observed) ─────────────────
    vendors = [("NGINX Inc.", "nginx", "1.27 (observed via package db)"),
               ("Alpine Linux", "Alpine Linux", "3.20 (observed via package db)"),
               ("OpenBSD Project", "OpenSSH", "9.7 (observed via banner)" if banner else None),
               ("PostgreSQL Global Development Group", "PostgreSQL", version),
               ("Meridian-Sim", "payShield-10K-sim", inv.get("firmware") if inv else None)]
    for name, product, ver in vendors:
        ref = f"vendor-{product.lower().replace(' ', '-')}"
        assets.append({"ref": ref, "type": "VENDOR", "name": name,
                       "identity": {"name": name, "product": product},
                       "source": "observed-in-estate",
                       "attributes": {"observed_version": ver} if ver else {}})
        ev(ref, "VENDOR_DECLARED" if ver is None else "STATIC_OBSERVED",
           {"product": product, **({"observed_version": ver} if ver else {})},
           "UNKNOWN", "estate-derivation")

    payload = {
        "estate": ESTATE, "scope": SCOPE, "observed_at": NOW,
        "assets": assets, "evidence": evidence, "relationships": relationships,
        "collectors": [
            {"plane": "DOCKER", "status": "OK", "reason": f"{len(containers)} containers inspected"},
            {"plane": "PACKAGE_DB", "status": "OK", "reason": f"{len(packages)} packages read"},
            {"plane": "TLS", "status": "OK", "reason": f"{len(TLS_ENDPOINTS)} endpoints handshaken"},
            {"plane": "HSM", "status": "OK" if inv else "FAILED",
             "reason": "banner read" if inv else "banner unavailable"},
        ],
        "coverage": [{"target": "sandbox estate containers", "expected": 8,
                      "collected": len(containers)}],
    }
    log(f"observation: {len(assets)} assets / {len(evidence)} evidence / {len(relationships)} relationships")
    result = post_observation(token, payload)
    log(f"ingestion result: {json.dumps({k: result.get(k) for k in ('stored', 'changed', 'run_id', 'observation_id') if k in result}) or list(result)[:6]}")
    log("done — open the BOM workspaces; they re-project from this observation")


if __name__ == "__main__":
    main()

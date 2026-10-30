"""Live synthetic bank services — real TLS listeners from a generated estate.

Spawns a sampled set of real TLS servers on 127.0.0.1 only, each backed by a
fresh synthetic private key held only in a private tmpfs (or 0700 temp dir).
A normal CryptoScan handshaker then probes them to produce live evidence.
No production addresses, no credential reuse, no external network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import socket
import ssl
import threading
import time
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from tools.banking_sandbox.common import open_estate, records, dump

ROOT = Path(__file__).resolve().parents[2]


def _synthetic_cert(work: Path, cn: str, san: str, key_type: str = "EC"):
    """Create a self-signed cert+key pair under work (0700), return (cert_pem, key_pem, cert_obj)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    if key_type == "RSA2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = work / f"{cn.replace('.', '_')}.pem"
    key_pem = work / f"{cn.replace('.', '_')}.key"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    key_pem.chmod(0o600)
    cert_pem.chmod(0o600)
    return cert_pem, key_pem, cert


def _collect_services(estate: Path, max_services: int = 24) -> list[dict[str, Any]]:
    """Sample services from network/*.jsonl — deterministic order, bounded."""
    services = []
    for f in sorted((estate / "public/network").glob("*.jsonl")):
        for row in records(f):
            # each row is an endpoint
            services.append(row)
            if len(services) >= max_services:
                break
        if len(services) >= max_services:
            break
    # Also add LB nodes if present (limited)
    lb_count = 0
    for inv in sorted((estate / "public/load_balancers").rglob("inventory.json")):
        try:
            data = json.loads(inv.read_text())
            for node in data.get("nodes", [])[:2]:
                # synthesize an LB frontend endpoint if not already covered
                if lb_count >= 6:
                    break
                services.append({
                    "bank_id": node.get("bank_id"),
                    "system_id": node.get("system_id") or node.get("lb_id"),
                    "app_id": node.get("lb_id"),
                    "endpoint_id": node.get("lb_id") + "-live-frontend",
                    "sni": node.get("lb_id") + ".lb.lab.invalid",
                    "zone": "lb-synthetic",
                    "synthetic": True,
                    "is_lb": True,
                    "lb_role": node.get("role"),
                })
                lb_count += 1
        except Exception:
            continue
        if len(services) >= max_services:
            break
    return services[:max_services]


def _start_one(cert_pem: Path, key_pem: Path, version: ssl.TLSVersion | None, port: int, ready_event: threading.Event, stop_event: threading.Event, label: str):
    """Simple TLS server — one handshake per connection, synthetic payload."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if version:
        ctx.minimum_version = ctx.maximum_version = version
    ctx.load_cert_chain(str(cert_pem), str(key_pem))
    # choose cipher for TLS1.2
    if version == ssl.TLSVersion.TLSv1_2:
        try:
            ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384")
        except Exception:
            pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
    except OSError as e:
        ready_event.set()
        return
    srv.listen(8)
    srv.settimeout(1.0)
    ready_event.set()
    while not stop_event.is_set():
        try:
            raw, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        def handle(conn):
            try:
                conn.settimeout(2.0)
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    try:
                        tls.send(b"SYNTHETIC LIVE BANK")
                    except Exception:
                        pass
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        threading.Thread(target=handle, args=(raw,), daemon=True).start()
    try:
        srv.close()
    except Exception:
        pass


def run_live(estate: Path, output: Path, port_base: int = 21000, max_services: int = 20, duration: float = 12.0) -> dict[str, Any]:
    """Create fresh output, start live synthetic listeners, probe them live, write results."""
    estate = Path(estate).resolve(strict=True)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("fresh output required")
    root, meta = open_estate(estate)
    services = _collect_services(root, max_services=max_services)
    if not services:
        raise ValueError("no services to make live")

    output.mkdir(mode=0o700, parents=True)
    work = Path(tempfile.mkdtemp(prefix="synthetic-live-", dir="/tmp"))
    work.chmod(0o700)
    # holders for threads
    stop_events = []
    threads = []
    ports = []
    certs = []

    start_ts = time.monotonic()
    try:
        # start each service
        for idx, svc in enumerate(services):
            port = port_base + idx
            cn = svc.get("endpoint_id") or svc.get("app_id") or f"svc-{idx}"
            san = svc.get("sni") or f"{cn}.lab.invalid"
            # alternate key types / versions to show variety
            key_type = "RSA2048" if idx % 2 == 0 else "EC"
            ver = ssl.TLSVersion.TLSv1_3 if idx % 3 == 0 else ssl.TLSVersion.TLSv1_2 if idx % 3 == 1 else None
            cert_pem, key_pem, cert_obj = _synthetic_cert(work, cn, san, key_type=key_type)
            certs.append((cn, cert_obj, port, svc, key_type, ver))
            ports.append(port)
            ready = threading.Event()
            stop = threading.Event()
            stop_events.append(stop)
            t = threading.Thread(target=_start_one, args=(cert_pem, key_pem, ver, port, ready, stop, cn), daemon=True)
            t.start()
            threads.append(t)
            ready.wait(timeout=2.0)
            # small stagger
            time.sleep(0.05)

        # give servers a moment
        time.sleep(0.4)

        # live probe via real handshaker
        import sys
        sys.path.insert(0, str(ROOT / "services/network_scanner"))
        from network_scanner.probing.tls_handshaker import handshake
        results = []
        for (cn, cert_obj, port, svc, key_type, ver) in certs:
            sni = svc.get("sni") or f"{cn}.lab.invalid"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2.5) as sock:
                    src = sock.getsockname()
                    res = handshake(sock, sni, timeout=2.5)
                    der = res.get("der")
                    # parse live cert for evidence
                    from cryptography import x509 as cx509
                    live_cert = cx509.load_der_x509_certificate(der) if der else None
                    fp = hashlib.sha256(der).hexdigest() if der else None
                    spki = None
                    if live_cert:
                        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                        spki = base64.b64encode(live_cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()
                    results.append({
                        "service": cn,
                        "bank_id": svc.get("bank_id"),
                        "system_id": svc.get("system_id"),
                        "endpoint_id": svc.get("endpoint_id"),
                        "sni": sni,
                        "port": port,
                        "live": True,
                        "source": list(src),
                        "destination": ["127.0.0.1", port],
                        "version": res.get("version"),
                        "cipher": res.get("cipher")[0] if res.get("cipher") else None,
                        "certificate_fingerprint_sha256": fp,
                        "certificate_spki_b64": spki,
                        "handshake_ok": True,
                        "termination": "synthetic-live-bank",
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                    })
                    try:
                        res["socket"].close()
                    except Exception:
                        pass
            except Exception as e:
                results.append({
                    "service": cn,
                    "port": port,
                    "sni": sni,
                    "live": False,
                    "error": f"{type(e).__name__}: {e}",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                })

        # hold live for remaining duration, or for preview if requested
        elapsed = time.monotonic() - start_ts
        remaining = max(0.0, duration - elapsed)
        if remaining > 0:
            time.sleep(min(remaining, 1.0))  # keep up briefly; long-running servers use run_daemon

        summary = {
            "estate": str(estate),
            "services_total": len(services),
            "live_listeners": len(ports),
            "ports": ports,
            "live_probed": len([r for r in results if r.get("handshake_ok")]),
            "live_failed": len([r for r in results if not r.get("handshake_ok")]),
            "wall_seconds": time.monotonic() - start_ts,
            "synthetic": True,
            "note": "Fresh synthetic private keys in 0700 tmpdir, destroyed after run. No production credentials. LB hop ownership from controlled topology, not inferred.",
        }
        dump(output / "live-summary.json", summary)
        # write detailed results
        (output / "live-results.jsonl").write_text("\n".join(json.dumps(r, sort_keys=True) for r in results) + "\n")
        # copy a small dashboard
        html = f"""<!doctype html><html><head><meta charset=utf-8><title>Synthetic Live Banks</title>
<style>body{{font:14px system-ui;background:#071326;color:#dce8ff;padding:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #2a3b5c;padding:8px;text-align:left}}th{{background:#13233f}}.ok{{color:#7ef0c2}}.bad{{color:#ff8d8d}}.muted{{color:#9bb0d0}}</style></head><body>
<h1>🔴 Synthetic Live Banks — running on 127.0.0.1</h1><p class=muted>Fresh keys in 0700 tmpdir, live handshakes via <code>tls_handshaker.handshake</code>. Not production banks.</p>
<pre>{json.dumps(summary, indent=2)}</pre>
<table><tr><th>service</th><th>bank</th><th>port</th><th>SNI</th><th>TLS</th><th>cipher</th><th>live</th></tr>
{"".join(f"<tr><td>{r.get('service')}</td><td>{r.get('bank_id') or ''}</td><td>{r.get('port')}</td><td>{r.get('sni')}</td><td>{r.get('version') or ''}</td><td>{r.get('cipher') or ''}</td><td class={'ok' if r.get('handshake_ok') else 'bad'}>{r.get('handshake_ok')}</td></tr>" for r in results)}
</table><p class=muted>Output: {output} • Estate: {estate} • <a href=\"/\">back to connected dashboard</a></p></body></html>"""
        (output / "index.html").write_text(html)
        return summary
    finally:
        for ev in stop_events:
            ev.set()
        time.sleep(0.2)
        # cleanup keys — best effort
        try:
            shutil.rmtree(work)
        except Exception:
            pass


def run_daemon(estate: Path, port_base: int = 21000, max_services: int = 20,
               dashboard_port: int = 8090) -> dict[str, Any]:
    """Start live listeners forever (for preview). Returns handle info; blocking."""
    estate = Path(estate).resolve(strict=True)
    root, meta = open_estate(estate)
    services = _collect_services(root, max_services=max_services)
    work = Path(tempfile.mkdtemp(prefix="synthetic-live-daemon-", dir="/tmp"))
    work.chmod(0o700)
    print(f"[live] estate {estate} -> {len(services)} synthetic live services on 127.0.0.1:{port_base}..", flush=True)
    stop_events = []
    for idx, svc in enumerate(services):
        port = port_base + idx
        cn = svc.get("endpoint_id") or svc.get("app_id") or f"svc-{idx}"
        san = svc.get("sni") or f"{cn}.lab.invalid"
        key_type = "RSA2048" if idx % 2 == 0 else "EC"
        ver = ssl.TLSVersion.TLSv1_3 if idx % 3 == 0 else ssl.TLSVersion.TLSv1_2 if idx % 3 == 1 else None
        cert_pem, key_pem, _ = _synthetic_cert(work, cn, san, key_type=key_type)
        ready = threading.Event()
        stop = threading.Event()
        stop_events.append(stop)
        threading.Thread(target=_start_one, args=(cert_pem, key_pem, ver, port, ready, stop, cn), daemon=True).start()
        ready.wait(timeout=2.0)
        print(f"[live] {cn} ({svc.get('bank_id')}) on 127.0.0.1:{port} san={san} key={key_type} ver={ver}", flush=True)

    # serve a tiny live index too — but only if the port is actually ours. A busy
    # dashboard port is a cosmetic problem: the TLS services are the point, and a
    # traceback from a background thread reads like the daemon failed.
    def index_server():
        from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
        import functools
        tmp = Path(tempfile.mkdtemp(prefix="live-index-"))
        html = f"""<!doctype html><html><head><meta charset=utf-8><title>Synthetic Live Banks — Dashboard</title>
<style>body{{font:14px system-ui;background:#071326;color:#dce8ff;padding:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #2a3b5c;padding:8px}}.ok{{color:#7ef0c2}}</style></head><body>
<h1>🔴 Synthetic Live Banks — daemon running</h1><p>Live synthetic TLS banks on <code>127.0.0.1:{port_base}..{port_base+len(services)-1}</code> • <code>{estate.name}</code> • {len(services)} services • keys in 0700 tmpdir {work}</p>
<table><tr><th>bank</th><th>service</th><th>port</th><th>SNI</th></tr>
{"".join(f"<tr><td>{s.get('bank_id')}</td><td>{s.get('endpoint_id') or s.get('app_id')}</td><td>{port_base+i}</td><td>{s.get('sni') or (s.get('endpoint_id') or '')+'.lab.invalid'}</td></tr>" for i,s in enumerate(services))}
</table><p>Probe: <code>openssl s_client -connect 127.0.0.1:{port_base} -servername bank-0001.lab.invalid -quiet</code> or use <code>services/network_scanner/probing/tls_handshaker.handshake</code>.</p></body></html>"""
        (tmp/"index.html").write_text(html)
        # bind in this thread so "address in use" is caught here, not in a thread
        return ThreadingHTTPServer(("0.0.0.0", dashboard_port),
                                   functools.partial(SimpleHTTPRequestHandler, directory=str(tmp)))

    if not dashboard_port:
        print("[live] index page disabled (--dashboard-port 0)", flush=True)
        server = None
    else:
        try:
            server = index_server()
        except OSError as exc:
            print(
                f"[live] no index page: 0.0.0.0:{dashboard_port} is not available ({exc.strerror or exc}). "
                f"The {len(services)} TLS services above are running; pass --dashboard-port to serve the index "
                f"elsewhere, or 0 to disable it",
                flush=True,
            )
            server = None
    if server is not None:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[live] dashboard on 0.0.0.0:{dashboard_port}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    for ev in stop_events:
        ev.set()

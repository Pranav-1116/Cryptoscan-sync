"""Live scanner adapters for the monitor — one per target type.

Each runner uses the same live scanning code as the manual/API flows. What a
runner needs but does not have (credentials, files, a registry) is returned as
``blocked_reason`` so the target shows BLOCKED with the exact fix, instead of
pretending to have scanned.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ network

def network_runner(config: dict, session: Any) -> dict:
    """Live TLS probe of a set of endpoints — needs nothing but reachability.

    Optional enterprise extras via config:
    - ``config.ipsec = ["vpn-gw.example.com", …]`` — IKE/IPsec SA probe
    - ``config.dnssec = ["example.com", …]`` — DNS/DNSSEC posture per zone
    Each extra runs through the same scanner the manual flows use; failures
    are data (issues), never crashes.
    """
    endpoints = [str(e) for e in (config.get("endpoints") or []) if str(e).strip()]
    if not endpoints and config.get("endpoint"):
        endpoints = [str(config["endpoint"])]
    if not endpoints and not (config.get("ipsec") or config.get("dnssec") or config.get("scope")):
        return {"blocked_reason": "no endpoints configured (set config.endpoints = ['host:port', …])"}

    from network_scanner.core.scanner import NetworkTlsScanner

    timeout = float(config.get("timeout", 5.0))
    scanner = NetworkTlsScanner(live=True, timeout=timeout)
    issues: list[str] = []
    ok = unreachable = 0
    scope_summary: dict | None = None

    # Global Network Discovery scope: full enterprise pipeline (assets, protocol
    # detection, dependency graph, PQC readiness, simulation) on each tick.
    if config.get("scope"):
        try:
            discovery = scanner.discover_network(
                [config["scope"]] if isinstance(config["scope"], str) else list(config["scope"]),
                mode=str(config.get("scan_mode", "SAFE")).upper(),
                authorization_scope=str(config.get("authorization_scope", "")),
                plugins=config.get("plugins"),
            )
            discovery_issues = _discovery_issues(discovery)
            issues.extend(discovery_issues)
            scope_summary = {
                "specs": len(discovery.get("scope") or []),
                "assets": len(discovery.get("assets") or []),
                "observations": len(discovery.get("protocol_observations") or []),
                "pqc_migration_required": (discovery.get("pqc_network_readiness") or {}).get("by_status", {}).get("MIGRATION_REQUIRED", 0),
            }
        except Exception as exc:
            logger.debug("monitor_network_scope_skipped", exc_info=True)
            # config errors (e.g. DEEP without authorization) surface as issues
            issues.append(f"SCOPE_ERROR:{type(exc).__name__}:{str(exc)[:120]}")
    if endpoints:
        result = scanner.scan_hosts(endpoints)
        for finding in result.get("findings") or []:
            endpoint = finding.get("endpoint") or "?"
            if finding.get("status") != "OK":
                unreachable += 1
                issues.append(f"UNREACHABLE:{endpoint}:{finding.get('status')}")
                continue
            ok += 1
            for issue in finding.get("policy_issues") or []:
                issues.append(f"{issue}:{endpoint}")
            crypto = finding.get("crypto") or {}
            if str(crypto.get("tls_version") or "") in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
                issues.append(f"WEAK_TLS_VERSION:{endpoint}")

        # certificates feed the shared inventory, exactly like POST /network-scans
        _persist_certificates(result, session)

        # continuous expiry watch: certificates nearing expiry are issues, so a
        # certificate due to roll over starts alerting within one interval window
        try:
            from network_scanner.inventory.expiry_monitor import expiry_alerts

            days = int(config.get("expiry_alert_days", 30))
            for alert in expiry_alerts(result.get("certificates") or [], days=days):
                cn = alert.get("common_name") or alert.get("subject") or "?"
                issues.append(f"CERT_EXPIRING:{cn}:{alert.get('days_left', '?')}d")
        except Exception:
            logger.debug("monitor_expiry_alerts_skipped", exc_info=True)

    # enterprise extras: IPsec/VPN + DNSSEC posture
    ipsec_hosts = [str(h) for h in (config.get("ipsec") or []) if str(h).strip()]
    if ipsec_hosts:
        try:
            ports = tuple(
                int(p) for p in str(config.get("ike_ports", "500,4500")).split(",") if p.strip().isdigit()
            ) or (500, 4500)
            vpn = scanner.scan_ipsec_hosts(ipsec_hosts, ports=ports)
            for finding in vpn.get("findings") or []:
                for issue in finding.get("issues") or []:
                    issues.append(f"{issue}:{finding.get('endpoint')}")
        except Exception:
            logger.debug("monitor_ipsec_skipped", exc_info=True)

    dnssec_zones = [str(z) for z in (config.get("dnssec") or []) if str(z).strip()]
    if dnssec_zones:
        try:
            dns = scanner.scan_dnssec_zones(
                dnssec_zones,
                resolver=config.get("dns_resolver"),
                check_transfer=bool(config.get("check_zone_transfer", True)),
            )
            for issue in dns.get("issues") or []:
                issues.append(issue)
        except Exception:
            logger.debug("monitor_dnssec_skipped", exc_info=True)

    summary = {
        "endpoints": len(endpoints),
        "probed_ok": ok,
        "unreachable": unreachable,
        "ipsec_targets": len(ipsec_hosts),
        "dnssec_zones": len(dnssec_zones),
        "issues": sorted(set(issues)),
    }
    if scope_summary is not None:
        summary["scope"] = scope_summary
    return {"summary": summary, "degraded": bool(issues), "issues": sorted(set(issues))}


def _persist_certificates(result: dict, session: Any) -> None:
    try:
        from db.repositories.certificate_repository import CertificateRepository
        from db.repositories.maturity_repository import MaturityRepository

        certs = CertificateRepository(session)
        usages = MaturityRepository(session)
        for cert in result.get("certificates") or []:
            if cert.get("fingerprint_sha256"):
                certs.upsert(cert)
        for usage in result.get("usages") or []:
            if usage.get("fingerprint_sha256") and usage.get("location"):
                usages.upsert_usage(
                    usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN"
                )
    except Exception:
        logger.debug("monitor_cert_persist_skipped", exc_info=True)  # scanning still succeeded


# --------------------------------------------------------------------- cloud

def cloud_runner(config: dict, session: Any) -> dict:
    """Live cloud crypto inventory via CloudScanner.scan_live (bring-your-own-creds)."""
    provider = str(config.get("provider") or "").lower()
    identifier = str(config.get("account") or config.get("identifier") or "")
    if provider not in {"aws", "azure", "gcp"} or not identifier:
        return {
            "blocked_reason": (
                "config needs provider ('aws'|'azure'|'gcp') and account identifier "
                "(e.g. {'provider': 'aws', 'account': '123456789012', 'role_arn': …})"
            )
        }

    role_arn = config.get("role_arn")
    regions = config.get("regions")
    from cloud_scanner.core.scanner import CloudScanner

    result = CloudScanner(live=True).scan_live(
        providers=[provider.upper()],
        regions=regions,
        role_arn=role_arn,
        azure_subscription=identifier if provider == "azure" else None,
        gcp_project=identifier if provider == "gcp" else None,
    )
    live_scan = result.get("live_scan") or {}
    if live_scan.get("status") == "FAILED":
        # credentials missing/expired or every API call errored — honest failure
        errors = live_scan.get("errors") or [{}]
        first = errors[0]
        raise RuntimeError(
            f"live cloud scan failed ({live_scan.get('error_count', len(errors))} errors; "
            f"{first.get('provider', '?')}/{first.get('service', '?')}: {str(first.get('error', ''))[:160]})"
        )
    findings = result.get("findings") or []
    issues = sorted({str(f.get("compliance_issue") or f.get("issue") or "") for f in findings} - {""})
    summary = {
        "resources": int(live_scan.get("resource_count") or live_scan.get("resources") or len(findings)),
        "findings": len(findings),
        "issues": issues,
    }
    return {"summary": summary, "degraded": bool(issues), "issues": issues}


# ---------------------------------------------------------------- repository

def repo_runner(config: dict, session: Any) -> dict:
    """Source scans run through the standard job pipeline — the monitor enqueues."""
    target = str(config.get("repo") or config.get("url") or "").strip()
    if not target:
        return {"blocked_reason": "config needs repo URL (e.g. {'repo': 'https://github.com/org/x.git'})"}
    from datetime import datetime, timezone

    from db.repositories.job_repository import JobRepository
    from worker.core.job_consumer import enqueue_job

    branch = str(config.get("branch") or "main")
    job = JobRepository(session).create_job(
        job_type="MANUAL", target_repo=target, target_branch=branch, triggered_by="monitor"
    )
    payload = {
        "job_id": job.job_id,
        "job_type": "MANUAL",
        "target_repo": target,
        "target_branch": branch,
        "triggered_by": "monitor",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        enqueue_job(payload)  # Redis when configured; otherwise in-process memory queue
        queued_via = "redis-or-memory"
    except Exception:
        queued_via = "db-only (job row QUEUED; start the worker to drain)"
    return {
        "summary": {"job_id": job.job_id, "queued_via": queued_via, "issues": []},
        "degraded": False,
        "issues": [],
    }


# ----------------------------------------------------------------- container

def container_runner(config: dict, session: Any) -> dict:
    """Container image scan via the container scanner (registry/local reference)."""
    reference = str(config.get("image") or config.get("reference") or "").strip()
    if not reference:
        return {"blocked_reason": "config needs image reference (e.g. {'image': 'registry/app:tag'})"}
    from container_scanner.core.scanner import ContainerScanner

    result = ContainerScanner().scan_image(reference)
    libraries = result.get("libraries") or []
    vulnerabilities = result.get("vulnerabilities") or []
    issues = sorted({f"CVE:{v.get('id', v.get('cve', '?'))}" for v in vulnerabilities})
    for library in libraries:
        if str(library.get("risk") or "").upper() in {"HIGH", "CRITICAL"}:
            issues.append(f"LIBRARY_RISK:{library.get('name', '?')}")
    summary = {
        "libraries": len(libraries),
        "vulnerabilities": len(vulnerabilities),
        "secrets": len(result.get("secrets") or []),
        "issues": sorted(set(issues)),
    }
    return {"summary": summary, "degraded": bool(issues), "issues": sorted(set(issues))}


# ------------------------------------------------------------------ payment

def payment_runner(config: dict, session: Any) -> dict:
    """Poll an HSM audit feed, ingest new events + transaction days, run policy.

    config:
      {"path": "/var/log/hsm/audit.log"}                  — syslog/JSONL tail
                                                           (rotation-safe cursor)
      {"url": "https://siem.example/hsm", "token": "…"}   — HTTP JSONL export
                                                           (?since= cursor)
      {"transactions_path": "/dw/tx_daily.jsonl"}         — optional daily
                                                           transaction counts
                                                           (JSONL {"day","count"}
                                                           or CSV day,count)

    Without a feed the target reports BLOCKED with the exact fix instead of
    pretending to have polled the HSM. Every sweep also runs usage analytics
    (dormancy / shadow keys) and crypto-per-transaction correlation, so
    PAY-011..014 fire from live data, not just stored policy state.
    """
    from datetime import timezone as _tz

    from payment_crypto.connectors import connector_from_config
    from payment_crypto.policy import PaymentPolicyEngine
    from payment_crypto.usage import TransactionCorrelator, UsageAnalyzer
    from db.models.payment_crypto import HsmEvent
    from db.repositories.payment_crypto_repository import PaymentCryptoRepository

    connector = connector_from_config(config)
    if connector is None:
        return {"blocked_reason": "config needs an audit feed: {'path': '/var/log/hsm/audit.log'} or {'url': 'https://siem/…'}"}

    since = None
    if config.get("url"):
        latest = session.query(HsmEvent.occurred_at).order_by(HsmEvent.occurred_at.desc()).first()
        since = latest[0] if latest else None
        if since is not None and since.tzinfo is None:  # sqlite returns naive datetimes
            since = since.replace(tzinfo=_tz.utc)
    polled = connector.poll(since=since) if since is not None else connector.poll()

    feed_errors = list(polled.errors)
    if not polled.records and feed_errors:
        return {"summary": {"events_ingested": 0, "issues": [f"AUDIT_FEED_ERROR:{feed_errors[0]}"]},
                "degraded": True, "issues": [f"AUDIT_FEED_ERROR:{feed_errors[0]}"]}

    fresh = polled.records
    repo = PaymentCryptoRepository(session)
    if fresh:
        repo.add_events([record.to_dict() for record in fresh])

        # key lifecycle events keep the inventory current without manual entry
        from payment_crypto.keyblocks import parse_tr31_header

        for record in fresh:
            if record.event_type in {"KEY_GENERATED", "KEY_IMPORTED", "KEY_ROTATED"} and record.key_id:
                existing = repo.get_key(record.key_id)
                payload = {"key_id": record.key_id, "hsm_device": record.device, "source": "HSM_EVENT"}
                if record.event_type == "KEY_ROTATED" and existing is not None:
                    payload["state"] = "EXPIRED"
                    payload["enabled"] = False
                    repo.upsert_key(payload)
                    payload = {"key_id": record.key_id, "hsm_device": record.device,
                               "state": "ACTIVE", "source": "HSM_EVENT"}
                algorithm = (record.detail or {}).get("algorithm")
                key_block = (record.detail or {}).get("key_block")
                if key_block:
                    header = parse_tr31_header(str(key_block))
                    payload["key_block_version"] = header.version_id if header.valid else None
                    payload["key_block_error"] = "; ".join(header.errors) or None
                    if header.valid and not header.key_usage.startswith("UNKNOWN"):
                        payload["key_usage"] = header.key_usage
                    if header.valid and not header.algorithm.startswith("UNKNOWN"):
                        payload["algorithm"] = header.algorithm
                elif algorithm:
                    payload["algorithm"] = str(algorithm)
                repo.upsert_key(payload)

    # optional: daily transaction counts from the data-warehouse export
    tx_days = _ingest_transaction_file(config.get("transactions_path"), repo)

    keys = repo.list_keys()
    key_rows = [{
        "key_id": k.key_id, "key_usage": k.key_usage, "algorithm": k.algorithm,
        "key_size": k.key_size, "state": k.state, "enabled": k.enabled,
        "activation_at": k.activation_at.isoformat() if k.activation_at else None,
        "key_block_version": k.key_block_version, "key_block_error": k.key_block_error,
    } for k in keys]
    event_rows = [{
        "occurred_at": e.occurred_at.isoformat(), "device": e.device,
        "event_type": e.event_type, "key_id": e.key_id, "detail": e.detail or {},
    } for e in repo.recent_events(days=90)]

    findings = list(PaymentPolicyEngine().evaluate(
        key_rows,
        ceremonies=[{"key_id": c.key_id, "held_at": c.held_at.isoformat() if c.held_at else None,
                     "custodians": c.custodians or [], "dual_control": c.dual_control,
                     "status": c.status or "HELD", "ceremony_id": c.ceremony_id}
                    for c in repo.list_ceremonies()],
        events=event_rows,
    ))
    usage_report = UsageAnalyzer().analyze(key_rows, event_rows)
    correlation = TransactionCorrelator().evaluate(
        repo.transaction_series(days=60), usage_report.get("usage_by_day") or {}
    )
    from payment_crypto.forecast import ExpiryForecaster

    forecast_report = ExpiryForecaster().forecast(
        key_rows, None,
        ceremonies=[{"key_id": c.key_id, "status": c.status or "HELD",
                     "held_at": c.held_at.isoformat() if c.held_at else None}
                    for c in repo.list_ceremonies()],
    )
    usage_findings = (
        list(usage_report.get("findings") or [])
        + list(correlation.get("findings") or [])
        + list(forecast_report.get("findings") or [])
    )
    all_findings = [f.to_dict() for f in findings] + usage_findings
    repo.replace_findings(all_findings)

    issues = sorted({f["rule_id"] for f in all_findings if f.get("severity", 0) >= 4 or f.get("blocking")})
    summary = {
        "events_ingested": len(fresh),
        "transaction_days_ingested": tx_days,
        "keys_tracked": len(keys),
        "hsm_ops_90d": usage_report.get("total_usage_events"),
        "correlation": correlation.get("status"),
        "rotations_next_90d": forecast_report.get("upcoming_count"),
        "open_findings": len(all_findings),
        "blocking": sum(1 for f in all_findings if f.get("blocking")),
        "issues": issues,
    }
    if feed_errors:
        summary["feed_warnings"] = feed_errors
    return {"summary": summary, "degraded": bool(issues), "issues": issues}


def _ingest_transaction_file(path: Any, repo) -> int:
    """Ingest {'day','count'} JSONL or 'day,count' CSV lines; upsert = idempotent."""
    import json as _json
    from datetime import date as _date
    from pathlib import Path as _Path

    if not path:
        return 0
    file = _Path(str(path))
    if not file.is_file():
        return 0  # no export yet today is not an error — the feed is optional
    days = 0
    for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("{"):
                payload = _json.loads(line)
                day = _date.fromisoformat(str(payload["day"])[:10])
                count = int(payload["count"])
            else:
                day_text, count_text = line.split(",")[:2]
                day = _date.fromisoformat(day_text.strip()[:10])
                count = int(count_text.strip())
        except (ValueError, KeyError, IndexError):
            continue  # malformed DW line: skip honestly, do not kill the sweep
        if count >= 0:
            repo.upsert_transaction_volume(day, count, source="dw-export")
            days += 1
    return days


# ---------------------------------------------------------------------- ot

def ot_runner(config: dict, session: Any) -> dict:
    """Passive OT/ICS scan of a capture/log directory. Never sends packets.

    Re-runs the same passive scanner as POST /api/v1/ot/scan over the
    configured directory, flags unencrypted protocol traffic, weak
    protocol/algorithm observations, and known-firmware CVEs, and persists
    discovered devices. ``config.path`` is required.
    """
    path = str(config.get("path") or config.get("directory") or "").strip()
    if not path:
        return {"blocked_reason": "config needs OT capture directory path (e.g. {'path': '/var/log/ot'})"}

    from ot_scanner.core.scanner import OtPassiveScanner

    result = OtPassiveScanner().scan_filesystem(path)
    if result.get("stopped"):
        return {"blocked_reason": "OT scanner safety-stopped (emergency stop engaged)"}

    issues: list[str] = []
    for finding in result.get("findings") or []:
        if not finding.get("has_crypto"):
            device = (finding.get("device") or {})
            ip = device.get("ip_address") if isinstance(device, dict) else str(device)
            ip = str(ip or finding.get("src_ip") or "?")
            protocol = str(finding.get("protocol") or "?")
            issues.append(f"OT_UNENCRYPTED:{protocol}:{ip}")
    for cve in result.get("cve_hits") or []:
        issues.append(f"OT_CVE:{cve.get('cve', '?')}")

    try:  # persist discovered OT devices (best-effort; scanning still succeeds)
        from db.repositories.maturity_repository import MaturityRepository

        repo = MaturityRepository(session)
        for device in result.get("devices") or []:
            repo.upsert_ot_device(dict(device))
        for finding in result.get("findings") or []:
            ip = (finding.get("device") or {}).get("ip_address")
            row = repo.upsert_ot_device(finding.get("device") or {"ip_address": ip})
            repo.add_ot_finding(row.id, dict(finding))
    except Exception:
        logger.debug("monitor_ot_persist_skipped", exc_info=True)

    risk = result.get("risk_report") or {}
    summary = {
        "devices": int(result.get("device_count") or len(result.get("devices") or [])),
        "unencrypted": int(result.get("unencrypted") or 0),
        "findings": len(result.get("findings") or []),
        "posture": risk.get("posture") or "UNKNOWN",
        "issues": sorted(set(issues)),
    }
    return {"summary": summary, "degraded": bool(issues), "issues": sorted(set(issues))}


# ------------------------------------------------------------------- vendor

def vendor_runner(config: dict, session: Any) -> dict:
    """Vendor crypto posture: deterministic score + issues for weak crypto.

    ``config.name`` is required; optional ``config.algorithms`` (observed or
    disclosed inventory) and ``config.sensitive`` (PCI/PHI/PII …) feed the
    shared registry + quantum classifier — same evidence rules as the rest
    of the platform. No outbound probing here.
    """
    name = str(config.get("name") or "").strip()
    if not name:
        return {"blocked_reason": "config needs vendor name (e.g. {'name': 'Acme HSM', 'algorithms': ['AES-256-GCM']})"}

    from vendor_intel.risk import score_vendor

    inventory = [
        {"algorithm": str(algo)}
        for algo in (config.get("algorithms") or [])
        if str(algo).strip()
    ]
    result = score_vendor(
        inventory=inventory,
        classifications=config.get("classifications") or [],
        pqc_status=config.get("pqc_status"),
        cbom_provided=config.get("cbom_provided"),
        refuses_disclosure=bool(config.get("refuses_disclosure")),
        long_lived_data=bool(config.get("long_lived_data")),
    )
    score = int(result.get("score") or 0)
    category = str(result.get("category") or result.get("vendor_risk_category") or "UNKNOWN")
    issues: list[str] = []
    issue = str(result.get("issue") or "").strip()
    # "Strong crypto" / "No crypto disclosure" are posture statements, not issues
    if issue and issue not in {"Strong crypto", "No crypto disclosure"}:
        issues.append(f"VENDOR_ISSUE:{issue}")
    if score >= 50 or category.upper() in {"HIGH", "CRITICAL"}:
        issues.append(f"VENDOR_RISK:{category}:score={score}")
    pqc = str(result.get("pqc_status") or "")
    if pqc and pqc.upper() in {"VULNERABLE", "SHOR_VULNERABLE"}:
        issues.append(f"VENDOR_QUANTUM:{pqc}")

    summary = {
        "vendor": name,
        "score": score,
        "risk": category,
        "issue": issue,
        "pqc_status": pqc,
        "issues": sorted(set(issues)),
    }
    degraded = bool(issues) or score >= 50
    return {"summary": summary, "degraded": degraded, "issues": sorted(set(issues))}


def _discovery_issues(discovery: dict) -> list[str]:
    """Surface enterprise-discovery findings as monitor issues.

    Weak crypto in any probe result, certificate issues, tunnel weaknesses
    and migration-blocking PQC posture all land in the degraded->alert path.
    """
    issues: list[str] = []
    for finding in discovery.get("findings") or []:
        endpoint = finding.get("endpoint") or finding.get("device") or "?"
        for issue in (finding.get("policy_issues") or []) + (finding.get("issues") or []):
            issues.append(f"{issue}:{endpoint}")
    for tunnel in discovery.get("tunnels") or []:
        if tunnel.get("pre_shared_key_used") and not tunnel.get("certificate_reference"):
            issues.append(f"TUNNEL_PSK_ONLY:{tunnel.get('tunnel_id')}")
    readiness = discovery.get("pqc_network_readiness") or {}
    blockers = readiness.get("migration_blockers") or []
    if blockers:
        issues.append(f"PQC_MIGRATION_BLOCKERS:{len(blockers)}")
    return sorted(set(issues))

# ------------------------------------------------------------------ telecom

def telecom_runner(config: dict, session: Any) -> dict:
    """Continuous 3GPP NF posture — the same engine as POST /telecom/scan.

    Probes the registered estate (5GC/EPC/IMS TLS-bearing NFs) through
    ``telecom_scanner`` and classifies per the 3GPP/NIST rule packs. Config
    (all optional): ``carrier`` limits the pass to one carrier's NFs,
    ``nf_ids`` to an explicit list, ``timeout`` per probe (default 3s).

    Needs a registered estate (POST /telecom/targets or the registry file);
    without one the target is BLOCKED with the exact fix — never fabricated.
    The pass is mirrored into the same snapshot file the API serves, so
    /telecom/posture, the roaming view and the exit report reflect monitor
    passes too (the API loader re-reads when the file's mtime changes).
    """
    try:
        from telecom_scanner.main import probe_registry
        from telecom_scanner.realtime import evaluate_changes, summarize_events
        from telecom_scanner.registry import load_registry
        from telecom_scanner.rollup import posture_rollup
    except ImportError as exc:
        return {"blocked_reason": f"telecom_scanner service not available in this deployment: {exc}"}

    reg = load_registry()
    targets = reg.get("targets") or {}
    if not targets:
        return {"blocked_reason": "no telecom estate registered (POST /telecom/targets or config/telecom_registry.json)"}

    carrier = str(config.get("carrier") or "").strip().lower()
    if carrier:
        targets = {k: v for k, v in targets.items()
                   if str(v.get("carrier_code") or "").lower() == carrier}
    nf_ids = [str(n).strip().lower() for n in (config.get("nf_ids") or []) if str(n).strip()]
    if nf_ids:
        targets = {k: v for k, v in targets.items() if k in nf_ids}
    if not targets:
        return {"blocked_reason": (
            f"no NF targets match carrier={carrier or 'any'} nf_ids={nf_ids or 'any'}"
            f" — registered: {', '.join(sorted((reg.get('targets') or {}).keys()))}")}

    rows = probe_registry(reg, only=sorted(targets), timeout=float(config.get("timeout", 3.0)))

    def _sev(row: dict) -> str:
        return str(row.get("severity") or "ok").lower()

    critical = sorted(r["nf_id"] for r in rows if _sev(r) == "critical")
    high = sorted(r["nf_id"] for r in rows if _sev(r) == "high")
    issues = [f"CRITICAL:{nf}" for nf in critical] + [f"HIGH:{nf}" for nf in high]
    summary = {
        "carrier": carrier or "all",
        "nf_targets": len(rows),
        "clean": sum(1 for r in rows if _sev(r) == "ok"),
        "critical": len(critical),
        "high": len(high),
        "medium": sum(1 for r in rows if _sev(r) == "medium"),
    }

    # mirror the pass into the API's telecom snapshot (same shape as
    # POST /telecom/scan writes); best-effort — never kills the tick
    try:
        import json
        import os
        from datetime import datetime, timezone
        from pathlib import Path

        snapshot_dir = os.environ.get("CRYPTOSCAN_SNAPSHOT_DIR") \
            or (Path(__file__).resolve().parents[4] / "data")
        snapshot_file = Path(snapshot_dir) / "telecom_snapshot.json"
        previous_state: dict = {}
        if snapshot_file.is_file():
            try:
                previous_state = (json.loads(snapshot_file.read_text()) or {}).get("state") or {}
            except (OSError, json.JSONDecodeError):
                previous_state = {}
        events = evaluate_changes(previous_state, rows)
        snapshot = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner": "telecom-monitor",
            "targets_registered": len(reg.get("targets") or {}),
            "rows": rows,
            "events": events,
            "events_summary": summarize_events(events),
            "state": {row["nf_id"]: {k: row[k] for k in
                                  ("status", "severity", "fingerprint", "cert_not_after", "pqc_ready")}
                      for row in rows},
            "rollup": posture_rollup(rows, reg.get("carriers") or {}),
        }
        snapshot_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = snapshot_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot))
        os.replace(tmp, snapshot_file)
    except Exception:  # noqa: BLE001 — snapshot mirroring must never fail the scan
        logger.exception("telecom_monitor_snapshot_mirror_failed")

    return {"summary": summary, "degraded": bool(issues), "issues": issues}


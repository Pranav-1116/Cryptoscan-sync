"""The five-family golden path: one payload, every hop, asserted.

The review's first blocker is that each component was proven and the *path*
between them was not. This harness takes one payload per collector family and
walks it through the whole chain:

    collector → API → evidence → DB → Twin → BOM → console

with the count **and identity** of what arrives asserted at every hop. A stage
that silently returns fewer assets, drops a fact, or changes a usage state
fails the family even when every hop "worked".

Five families, chosen because a bank's first deployment runs them:

    runtime     a process tree with a mapped library and a listening endpoint
    static      a source file with a hard-coded algorithm
    network_tls a completed TLS handshake's decomposition
    pki         a certificate in the inventory
    cloud       managed-service TLS configuration from AWS

Honesty rules, carried from the rest of this repo:

* **The collector is real code.** Runtime runs the agent's ``collect_runtime``
  against a fake ``/proc``; cloud runs ``collect_cloud`` against an injected AWS
  transport; network/static/PKI run the API's collectors against rows written in
  the scanner's own shape. Where the *transport* is injected, the row says so.
* **A stage that cannot be executed is reported, not skipped.** ``SKIPPED`` is
  not a pass and fails the family's completeness.
* **The UI stage proves a caller and a rendered test exist** for the endpoints
  the earlier stages read. It does not prove this payload renders on a screen.

Run::

    python scripts/golden_path.py \\
        --json docs/bank-environment/113-golden-path.json \\
        --md   docs/bank-environment/113-golden-path.md
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA = "cryptoscan.golden-path/1"
VERSION = "golden-path/1.0"

TENANT = "tenant-golden-path"

PASS = "PASS"
FAIL = "FAIL"
SKIPPED = "SKIPPED"

REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = REPO_ROOT / "frontend" / "src"

#: the console reads the twin and BOM stages produced, by the paths it calls
CONSOLE_ENDPOINTS = (
    ("catalog", "/api/v1/estate/evidence/catalog/assets"),
    ("boms", "/api/v1/estate/evidence/boms"),
    ("bom-components", "/api/v1/estate/evidence/boms?bom="),
)


# ------------------------------------------------------------------- fixture --- #
def _database() -> tuple[Any, Any]:
    """A fresh in-memory database with the whole ORM metadata registered."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers the metadata
    from db.models.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)(), engine


def _tenant_scope():
    from db.tenancy import tenant_scope

    return tenant_scope(TENANT)


def _fake_proc() -> str:
    """One nginx mapping libcrypto, listening on 443 — the agent's own input shape."""
    base = Path(tempfile.mkdtemp(prefix="golden-proc-"))
    pid = base / "101"
    pid.mkdir()
    (pid / "comm").write_text("nginx\n", encoding="utf-8")
    (pid / "cmdline").write_text("nginx: master process\x00", encoding="utf-8")
    (pid / "maps").write_text(
        "7f0000000000-7f0000010000 r--p 00000000 08:01 100 /usr/lib/libcrypto.so.3\n",
        encoding="utf-8",
    )
    (pid / "cgroup").write_text("0::/system.slice/nginx.service\n", encoding="utf-8")
    net = base / "net"
    net.mkdir()
    (net / "tcp").write_text(
        "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 000000 0 0 9001\n",
        encoding="utf-8",
    )
    (pid / "fd").mkdir()
    os.symlink("socket:[9001]", pid / "fd" / "3")
    return str(base)


def _aws_transport():
    """An injected AWS control plane: one load balancer with a TLS-1-2 policy.

    Every other call is AccessDenied, which is realistic and keeps the cloud
    family's "CONFIGURED, never OBSERVED" claim testable.
    """
    from urllib.parse import parse_qs, urlparse

    lb = (
        "<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>"
        "<LoadBalancerArn>arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/payments/1"
        "</LoadBalancerArn><DNSName>payments-1.eu-west-1.elb.amazonaws.com</DNSName>"
        "<LoadBalancerName>payments</LoadBalancerName><Scheme>internet-facing</Scheme>"
        "<Type>application</Type><State><Code>active</Code></State></member></LoadBalancers>"
        "</DescribeLoadBalancersResult></DescribeLoadBalancersResponse>"
    )
    listeners = (
        "<DescribeListenersResponse><DescribeListenersResult><Listeners><member>"
        "<Protocol>HTTPS</Protocol><Port>443</Port>"
        "<SslPolicy>ELBSecurityPolicy-TLS-1-2-2017-01</SslPolicy><Certificates><member>"
        "<CertificateArn>arn:aws:acm:eu-west-1:1:certificate/abc</CertificateArn>"
        "</member></Certificates></member></Listeners></DescribeListenersResult>"
        "</DescribeListenersResponse>"
    )

    def transport(method, url, headers, body, timeout):  # noqa: ARG001 — transport signature
        query = parse_qs(urlparse(url).query)
        action = (query.get("Action") or [""])[0]
        if "DescribeLoadBalancers" in action:
            return 200, lb.encode()
        if "DescribeListeners" in action:
            return 200, listeners.encode()
        return 403, b'{"__type":"AccessDeniedException"}'

    return transport


# ------------------------------------------------------------------ families --- #
@dataclass
class Family:
    """One collector family's payload, its planted identities and its expectations."""

    name: str
    plane: str
    transport: str                     #: what produced the input the collector read
    collect: Callable[[Any], dict[str, Any]]
    #: identities that must survive every hop, as (stage, predicate) pairs
    assets: int                        #: assets the collector is expected to emit
    evidence: int                      #: evidence records expected
    bom: str                           #: the BOM this family must reach
    #: component predicate for the BOM stage
    bom_match: Callable[[dict[str, Any]], bool]
    #: (fact_type, value) that must appear CURRENT in the observation store
    fact: tuple[str, str] | None
    #: a family-specific honesty assertion verified at the API stage
    api_check: Callable[[dict[str, Any]], tuple[bool, str]] | None = None


def _seed_static(db: Any) -> None:
    from db.models.crypto_asset import CryptoAsset

    db.add_all([
        CryptoAsset(tenant_id=TENANT, algorithm="RSA", key_size=2048, mode=None, purpose="SIGNATURE",
                    file_path="src/pay/Sign.java", line_number=42, confidence="HIGH",
                    occurrence_count=1, scanner_ids=["golden"]),
        CryptoAsset(tenant_id=TENANT, algorithm="AES", key_size=256, mode="GCM", purpose="ENCRYPTION",
                    file_path="src/pay/Bulk.java", line_number=88, confidence="HIGH",
                    occurrence_count=1, scanner_ids=["golden"]),
    ])
    db.commit()


def _seed_network(db: Any) -> None:
    from db.repositories.scan_run_repository import ScanRunRepository

    record = {
        "evidence_id": "net-golden-1",
        "target": {"endpoint": "payments.bank.example:443", "host": "payments.bank.example",
                   "port": 443, "ip_address": "10.20.10.5"},
        "protocol": "TLS",
        "evidence_type": "NETWORK_ACTIVE_OBSERVED",
        "observation_status": "OBSERVED",
        "tls_version": "TLSv1.2",
        "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "decomposition": {
            "key_exchange": "ECDHE", "key_exchange_size": 256,
            "authentication": "RSA", "authentication_size": 2048,
            "bulk_cipher": "AES", "bulk_size": 256, "bulk_mode": "GCM",
        },
        "certificate": {"fingerprint_sha256": "ab" * 32},
        "mutual_tls": True,
        "policy_issues": [],
        "limitations": ["observed from outside the DMZ; proxy terminations upstream are invisible here"],
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    # the payload shape ``persist_network`` writes: network_evidence at the top level
    row = ScanRunRepository(db).create_run(
        {"network_evidence": [record], "collection": {"schema": "cryptoscan.network-collection/1",
                                                      "kind": "crypto-observe"}},
        target_kind="crypto-observe")
    row.tenant_id = TENANT
    db.commit()


def _seed_pki(db: Any) -> None:
    from db.models.certificate import Certificate

    now = datetime.now(timezone.utc)
    db.add(Certificate(
        tenant_id=TENANT,
        fingerprint_sha256="cd" * 32,
        subject="CN=payments.bank.example",
        issuer="CN=Bank Issuing CA",
        serial_number="0a1b2c",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=90),
        public_key_algorithm="RSA",
        public_key_size=2048,
        expiry_status="VALID",
        days_until_expiry=90,
        is_self_signed=False,
        san=["payments.bank.example"],
        usages=["serverAuth"],
    ))
    db.commit()


def _collect_runtime(_db: Any) -> dict[str, Any]:
    from api import host_collect

    return host_collect.collect_runtime(proc_base=_fake_proc())


def _collect_static(db: Any) -> dict[str, Any]:
    from api import estate_discovery

    _seed_static(db)
    return estate_discovery.collect_static(db)


def _collect_network(db: Any) -> dict[str, Any]:
    from api import estate_discovery

    _seed_network(db)
    return estate_discovery.collect_network(db)


def _collect_pki(db: Any) -> dict[str, Any]:
    from api import estate_discovery

    _seed_pki(db)
    return estate_discovery.collect_pki(db)


def _collect_cloud(_db: Any) -> dict[str, Any]:
    from api import estate_cloud

    config = {"access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "injected",
              "session_token": None, "region": "eu-west-1",
              "endpoint": "https://aws.test", "source": "INJECTED"}
    return estate_cloud.collect_cloud(None, transport=_aws_transport(), config=config)


FAMILIES: tuple[Family, ...] = (
    Family(
        name="runtime", plane="RUNTIME",
        transport="the agent's collect_runtime over a fake /proc tree",
        collect=_collect_runtime, assets=3, evidence=3, bom="SBOM",
        bom_match=lambda c: str(c.get("name") or "").lower() == "openssl",
        fact=("attribute:process", "nginx"),
        api_check=lambda resp: (
            resp["summary"]["crypto"]["by_usage_state"]["OBSERVED"] == 0,
            "a mapped library must not become an OBSERVED crypto artefact",
        ),
    ),
    Family(
        name="static", plane="STATIC",
        transport="the API's collect_static over crypto_assets rows the static scanner writes",
        collect=_collect_static, assets=2, evidence=2, bom="CBOM",
        bom_match=lambda c: str(c.get("algorithm") or "") == "RSA" and c.get("key_size") == 2048,
        fact=("crypto:algorithm", "RSA"),
    ),
    Family(
        name="network_tls", plane="NETWORK",
        transport="the API's collect_network over a network scan run the TLS scanner writes",
        collect=_collect_network, assets=1, evidence=1, bom="NBOM",
        bom_match=lambda c: str(c.get("name") or "").startswith("payments.bank.example"),
        fact=("attribute:protocol", "TLS"),
    ),
    Family(
        name="pki", plane="PKI",
        transport="the API's collect_pki over certificate inventory rows",
        collect=_collect_pki, assets=1, evidence=1, bom="CBOM",
        bom_match=lambda c: "payments.bank.example" in str(c.get("name") or ""),
        fact=("attribute:issuer", "CN=Bank Issuing CA"),
    ),
    Family(
        name="cloud", plane="CLOUD",
        transport="collect_cloud over an injected AWS control plane (ELBv2 TLS policy)",
        # one load balancer plus the ACM certificate its listener cites
        collect=_collect_cloud, assets=2, evidence=2, bom="NBOM",
        bom_match=lambda c: str(c.get("name") or "") == "payments",
        fact=("attribute:type", "application"),
        api_check=lambda resp: (
            resp["summary"]["crypto"]["by_usage_state"]["OBSERVED"] == 0,
            "cloud configuration must stay CONFIGURED, never OBSERVED",
        ),
    ),
)

FAMILIES_BY_NAME = {family.name: family for family in FAMILIES}


# -------------------------------------------------------------------- stages --- #
@dataclass
class Stage:
    name: str
    verdict: str
    detail: str
    observations: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"stage": self.name, "verdict": self.verdict, "detail": self.detail,
                "observations": self.observations}


def _fail(stage: str, detail: str, **observations: Any) -> Stage:
    return Stage(stage, FAIL, detail, observations)


def stage_collect(family: Family, db: Any) -> tuple[Stage, dict[str, Any]]:
    package = family.collect(db)
    assets = package.get("assets") or []
    evidence = package.get("evidence") or []
    observations = {
        "assets": len(assets),
        "evidence": len(evidence),
        "relationships": len(package.get("relationships") or []),
        "asset_names": [str(a.get("name") or a.get("asset_id")) for a in assets][:8],
        "evidence_types": sorted({str(e.get("evidence_type")) for e in evidence}),
    }
    if len(assets) != family.assets:
        return _fail("collect", f"the collector emitted {len(assets)} assets, expected {family.assets}",
                     **observations), package
    if len(evidence) != family.evidence:
        return _fail("collect",
                     f"the collector emitted {len(evidence)} evidence records, expected {family.evidence}",
                     **observations), package
    if not evidence or not all(e.get("target") for e in evidence):
        return _fail("collect", "an evidence record does not name the asset it belongs to",
                     **observations), package
    targets = {str(e.get("target")) for e in evidence}
    refs = {str(a.get("ref") or a.get("asset_id")) for a in assets}
    missing = sorted(targets - refs)
    if missing:
        return _fail("collect", f"evidence cites {missing} which the collector never emitted",
                     **observations), package
    observations["every_evidence_record_has_its_asset"] = True
    return Stage("collect", PASS,
                 f"{len(assets)} assets, {len(evidence)} evidence records, every record names its asset",
                 observations), package


def stage_api(family: Family, db: Any, package: dict[str, Any]) -> tuple[Stage, dict[str, Any] | None]:
    from api.routers.estate_graph import EstateDiscoverRequest, run_discovery
    from shared_models.estate_graph import collector_outcome

    assets = package.get("assets") or []
    evidence = package.get("evidence") or []
    body = EstateDiscoverRequest(
        estate=f"golden-{family.name}",
        scope="qualification",
        assets=assets,
        evidence=evidence,
        relationships=package.get("relationships") or [],
        collectors=[collector_outcome(family.plane, "COMPLETE",
                                      expected=len(assets), collected=len(assets))],
        coverage=[{"plane": family.plane, "status": "COMPLETE",
                   "expected": len(assets), "collected": len(assets)}],
        include_boms=True,
        persist=True,
    )
    response = run_discovery(db, "golden-path", body)
    summary = response.get("summary") or {}
    observations = {
        "run_id": response.get("run_id"),
        "projection_id": response.get("projection_id"),
        "assets": summary.get("assets"),
        "evidence": summary.get("evidence"),
        "bom_counts": response.get("bom_counts"),
        "crypto_usage_states": (summary.get("crypto") or {}).get("by_usage_state"),
    }
    if not response.get("run_id"):
        return _fail("api", "the discovery did not persist a run", **observations), None
    if int(summary.get("assets") or 0) != len(assets):
        return _fail("api", f"the API graph holds {summary.get('assets')} assets, "
                            f"the collector sent {len(assets)}", **observations), None
    if int(summary.get("evidence") or 0) != len(evidence):
        return _fail("api", f"the API graph holds {summary.get('evidence')} evidence records, "
                            f"the collector sent {len(evidence)}", **observations), None
    if family.api_check is not None:
        ok, why = family.api_check(response)
        if not ok:
            return _fail("api", why, **observations), response
    return Stage("api", PASS,
                 f"one run persisted ({(response.get('run_id') or '')[:8]}), "
                 f"{summary.get('assets')} assets and {summary.get('evidence')} evidence records "
                 "survived normalisation unchanged", observations), response


def stage_evidence(family: Family, db: Any, response: dict[str, Any],
                   package: dict[str, Any]) -> Stage:
    from sqlalchemy import select

    from db.models.estate_catalog import EstateEvidenceRecord

    rows = list(db.execute(
        select(EstateEvidenceRecord).where(EstateEvidenceRecord.tenant_id == TENANT)
    ).scalars())
    observations = {"evidence_rows": len(rows),
                    "evidence_types": sorted({str(r.evidence_type) for r in rows})}
    if not rows:
        return _fail("evidence", "the discovery wrote no evidence rows", **observations)
    written = (response.get("evidence_store") or {}).get("evidence") or {}
    if int(written.get("total") or 0) != len(rows):
        return _fail("evidence",
                     f"the sync reported {written.get('total')} evidence rows but {len(rows)} exist",
                     **observations)
    if int(written.get("created") or 0) != len(rows):
        return _fail("evidence", f"{written.get('created')} of {len(rows)} evidence rows were created",
                     **observations)
    ids = [str(r.evidence_id) for r in rows]
    if len(set(ids)) != len(ids) or not all(ids):
        return _fail("evidence", "evidence rows are not content-addressed to distinct ids",
                     **observations)
    # the collector's target must survive: an evidence row that cannot name its
    # asset cannot be attributed, which is the failure this stage exists to catch
    targets = {str(r.target_id) for r in rows}
    observations["evidence_ids"] = sorted(ids)[:8]
    observations["targets"] = sorted(targets)[:8]
    if not all(targets):
        return _fail("evidence", "an evidence row does not name the asset it belongs to",
                     **observations)
    # the stored target is the resolved catalogue identity, so it is checked against
    # the catalogue — and its count against what the collector actually sent
    from db.models.estate_catalog import EstateAssetRecord

    catalogue_ids = {str(r) for r in db.execute(
        select(EstateAssetRecord.asset_id).where(EstateAssetRecord.tenant_id == TENANT)
    ).scalars()}
    sent = {str(e.get("target")) for e in (package.get("evidence") or [])}
    stray = sorted(targets - catalogue_ids)
    observations["collector_targets"] = len(sent)
    if stray:
        return _fail("evidence", f"stored evidence cites {stray}, which the catalogue never resolved",
                     **observations)
    if len(targets) != len(sent):
        return _fail("evidence", f"{len(sent)} collector targets resolved to {len(targets)} evidence "
                                 "targets", **observations)
    # every stored record must carry facts — an empty record is a receipt, not evidence
    empty = [r.evidence_id for r in rows if not (r.facts or {})]
    if empty:
        return _fail("evidence", f"{len(empty)} evidence rows carry no facts", **observations)
    observations["fact_keys"] = sorted({k for r in rows for k in (r.facts or {})})[:10]
    return Stage("evidence", PASS,
                 f"{len(rows)} content-addressed evidence rows, each naming the collector's target and "
                 f"carrying its facts ({len(observations['fact_keys'])} keys)", observations)


def stage_db(family: Family, db: Any) -> Stage:
    from sqlalchemy import select

    from db.models.estate_catalog import EstateAssetRecord, EstateObservationRecord

    assets = list(db.execute(
        select(EstateAssetRecord).where(EstateAssetRecord.tenant_id == TENANT)
    ).scalars())
    facts = list(db.execute(
        select(EstateObservationRecord).where(
            EstateObservationRecord.tenant_id == TENANT,
            EstateObservationRecord.lifecycle_state == "CURRENT",
        )
    ).scalars())
    observations = {"asset_rows": len(assets), "current_facts": len(facts),
                    "fact_types": sorted({str(f.fact_type) for f in facts})}
    if len(assets) != family.assets:
        return _fail("db", f"the catalogue holds {len(assets)} assets, the collector emitted "
                           f"{family.assets}", **observations)
    if not facts:
        return _fail("db", "the observation store holds no CURRENT facts", **observations)
    if family.fact is not None:
        fact_type, expected = family.fact
        matched = [f for f in facts if str(f.fact_type) == fact_type and str(f.value) == expected]
        observations["fact_checked"] = {"fact_type": fact_type, "value": expected,
                                        "matched": len(matched)}
        if not matched:
            seen = sorted({f"{f.fact_type}={f.value}" for f in facts})[:10]
            return _fail("db", f"no CURRENT fact {fact_type}={expected}; the store holds {seen}",
                         **observations)
    return Stage("db", PASS,
                 f"{len(assets)} catalogue assets and {len(facts)} CURRENT facts, including "
                 f"{family.fact[0]}={family.fact[1]}", observations)


def stage_twin(family: Family, db: Any) -> Stage:
    from api import estate_catalog, estate_observations

    rows = estate_catalog.list_assets(db, tenant_id=TENANT, limit=50)
    if len(rows) != family.assets:
        return _fail("twin", f"the twin lists {len(rows)} assets, expected {family.assets}")
    histories = []
    for row in rows:
        detail = estate_catalog.asset_detail(db, row.asset_id, tenant_id=TENANT) or {}
        if not detail.get("asset"):
            return _fail("twin", f"the twin returned no detail for {row.asset_id}")
        histories.append(estate_observations.history(db, row.asset_id, tenant_id=TENANT))
    fact_types = sorted({t for h in histories for t in (h.get("fact_types") or [])})
    history_facts = sum(int(h.get("fact_count") or 0) for h in histories)
    observations = {
        "twin_assets": len(rows),
        "history_facts": history_facts,
        "history_fact_types": fact_types[:10],
    }
    if not history_facts:
        return _fail("twin", "the twin's observation history is empty", **observations)
    if family.fact is not None and str(family.fact[0]) not in fact_types:
        return _fail("twin", f"the twin's history does not carry {family.fact[0]}", **observations)
    return Stage("twin", PASS,
                 f"{len(rows)} assets readable with detail; {history_facts} facts of history across them",
                 observations)


def stage_bom(family: Family, response: dict[str, Any] | None) -> Stage:
    if response is None:
        return _fail("bom", "no discovery response to project from")
    boms = response.get("boms") or {}
    if not boms:
        return _fail("bom", "the discovery returned no BOM projections")
    components = (boms.get(family.bom) or {}).get("components") or []
    observations = {
        "bom": family.bom,
        "components": len(components),
        "counts": response.get("bom_counts"),
        "all_boms_share_snapshot": (response.get("consistency") or {}).get("all_boms_share_snapshot"),
    }
    if not components:
        return _fail("bom", f"{family.bom} has no components for this family", **observations)
    matched = [c for c in components if family.bom_match(c)]
    observations["matched"] = len(matched)
    if not matched:
        names = [str(c.get("name") or c.get("algorithm") or c.get("bom_ref")) for c in components][:6]
        return _fail("bom", f"{family.bom} carries no component matching the planted identity "
                            f"(found {names})", **observations)
    if not observations["all_boms_share_snapshot"]:
        return _fail("bom", "the BOMs do not share one snapshot id", **observations)
    return Stage("bom", PASS,
                 f"{family.bom} carries {len(matched)} of {len(components)} components matching the "
                 "planted identity, and all six BOMs share one projection id", observations)


def _api_symbols(path: str) -> list[str]:
    """Console client functions in ``lib/api.ts`` that call ``path``."""
    api = FRONTEND / "lib" / "api.ts"
    if not api.exists():
        return []
    text = api.read_text(encoding="utf-8")
    symbols: list[str] = []
    cursor = 0
    for match in re.finditer(re.escape(path), text):
        before = text[: match.start()]
        decl = list(re.finditer(r"export const (\w+)", before))
        if not decl:
            continue
        name = decl[-1].group(1)
        # only an adjacent declaration counts: a symbol declared hundreds of lines
        # earlier is a different endpoint
        if before[match.start() if False else 0 :].count("\n") - before[: decl[-1].start()].count("\n") <= 6:
            symbols.append(name)
        cursor = match.end()  # noqa: F841 — kept for clarity
    return sorted(set(symbols))


def _needles(path: str) -> set[str]:
    """The endpoint path and its parent — a test may mock either, by prefix."""
    base = path.split("?")[0]
    return {base, base.rsplit("/", 1)[0]}


def _console_reach(symbols: list[str], path: str) -> tuple[list[str], list[str]]:
    """Console files that call the symbols, and rendered tests that exercise them."""
    callers: list[str] = []
    tests: list[str] = []
    if not FRONTEND.exists() or not symbols:
        return callers, tests
    needles = _needles(path)
    for file in sorted(FRONTEND.rglob("*.ts*")):
        if not file.is_file() or file.name == "api.ts":
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except OSError:
            continue
        hit = any(symbol in text for symbol in symbols) or any(n in text for n in needles)
        if not hit:
            continue
        relative = str(file.relative_to(REPO_ROOT))
        (tests if ".test." in file.name else callers).append(relative)
    return sorted(callers), sorted(tests)


def stage_ui(family: Family) -> Stage:
    """Does the console read what the previous stages produced?

    Deliberately a *caller* check: it proves the console has a client function for
    each endpoint and a rendered test that exercises it. It does not render this
    payload, and the report says so rather than implying a browser test.
    """
    findings: dict[str, Any] = {}
    missing: list[str] = []
    for label, path in CONSOLE_ENDPOINTS:
        symbols = _api_symbols(path)
        callers, tests = _console_reach(symbols, path)
        findings[label] = {"path": path, "client_symbols": symbols,
                           "callers": callers[:4], "tests": tests[:3],
                           "caller_count": len(callers), "test_count": len(tests)}
        if not symbols or not callers or not tests:
            missing.append(label)
    if missing:
        return _fail("ui", f"the console has no client function + caller + rendered test for {missing}",
                     **findings)
    consumers = sorted({Path(c).name for f in findings.values() for c in f["callers"]})[:5]
    return Stage("ui", PASS,
                 f"all {len(CONSOLE_ENDPOINTS)} endpoints have a console client, a caller "
                 f"({', '.join(consumers)}) and a rendered test; this payload is not rendered here",
                 findings)


UUID_LIKE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def detect_defects(family: Family, db: Any) -> list[dict[str, Any]]:
    """Defects the path exposes without breaking it — found, not fixed here."""
    from sqlalchemy import select

    from db.models.estate_catalog import EstateAssetRecord

    found: list[dict[str, Any]] = []
    for asset in db.execute(
        select(EstateAssetRecord).where(EstateAssetRecord.tenant_id == TENANT)
    ).scalars():
        name = str(asset.name or "")
        if UUID_LIKE.match(name) and asset.location:
            found.append({
                "id": "asset-named-by-raw-identifier",
                "family": family.name,
                "asset_id": asset.asset_id,
                "detail": (f"the catalogue names this asset {name!r} while its location is "
                           f"{asset.location!r} — a reader sees a row identifier where an "
                           "application name belongs"),
                "severity": "identity-quality",
                "affects": "Twin and console labels; identity resolution is unaffected",
            })
    return found


# ------------------------------------------------------------------- measure --- #
def run_family(family: Family) -> dict[str, Any]:
    """Walk one payload through every hop, on a fresh database."""
    db, engine = _database()
    stages: list[Stage] = []
    defects: list[dict[str, Any]] = []
    try:
        with _tenant_scope():
            collect_stage, package = stage_collect(family, db)
            stages.append(collect_stage)
            if collect_stage.verdict != PASS:
                return _family_row(family, stages, None, defects)
            api_stage, response = stage_api(family, db, package)
            stages.append(api_stage)
            if response is None:
                return _family_row(family, stages, response, defects)
            stages.extend([
                stage_evidence(family, db, response, package),
                stage_db(family, db),
                stage_twin(family, db),
                stage_bom(family, response),
            ])
            defects = detect_defects(family, db)
        stages.append(stage_ui(family))
    finally:
        db.close()
        engine.dispose()
    return _family_row(family, stages, None, defects)


def _family_row(family: Family, stages: list[Stage], response: Any,
                defects: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    names = ("collect", "api", "evidence", "db", "twin", "bom", "ui")
    by_name = {stage.name: stage for stage in stages}
    ordered = [by_name.get(name) or Stage(name, SKIPPED, "not reached: an earlier hop failed")
               for name in names]
    failures = [stage.name for stage in ordered if stage.verdict == FAIL]
    skipped = [stage.name for stage in ordered if stage.verdict == SKIPPED]
    if failures:
        verdict = FAIL
    elif skipped:
        verdict = SKIPPED
    else:
        verdict = PASS
    return {
        "family": family.name,
        "plane": family.plane,
        "transport": family.transport,
        "verdict": verdict,
        "stages_passed": sum(1 for stage in ordered if stage.verdict == PASS),
        "stages_total": len(ordered),
        "failed_stages": failures,
        "skipped_stages": skipped,
        "stages": [stage.as_dict() for stage in ordered],
        "defects": defects or [],
    }


def measure(only: list[str] | None = None) -> dict[str, Any]:
    wanted = set(only) if only else None
    rows = [run_family(family) for family in FAMILIES
            if wanted is None or family.name in wanted]
    families_passed = sum(1 for row in rows if row["verdict"] == PASS)
    stages_total = sum(row["stages_total"] for row in rows)
    stages_passed = sum(row["stages_passed"] for row in rows)
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant": TENANT,
        "families": len(rows),
        "expected_families": len(FAMILIES),
        "families_passed": families_passed,
        "stages_total": stages_total,
        "stages_passed": stages_passed,
        "complete": families_passed == len(FAMILIES) and len(rows) == len(FAMILIES),
        "rows": rows,
        "defects": [d for row in rows for d in row["defects"]],
        "limits": [
            "The collector code is real, but the input it reads is not a bank's: /proc is a "
            "fixture, the AWS transport is injected, and the static/network/PKI rows are written "
            "in the scanner's own shape rather than produced by running the scanner.",
            "The UI stage proves a console caller and a rendered test exist for the endpoints the "
            "earlier hops read. It does not render this payload, and no browser was involved.",
            "Each family runs on its own empty SQLite database, so this is five single-family "
            "paths, not one estate where the families interact (identity merging across planes, "
            "conflicts, and change detection are covered by their own suites).",
            "Only the five families a first deployment runs are here. Kubernetes, CMDB, KMS, HSM, "
            "hardware and vendor planes are not part of this path.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# The five-family golden path — one payload, every hop",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['families_passed']} / {report['families']} families passed · "
        f"{report['stages_passed']} / {report['stages_total']} hops**",
        "",
        "collector → API → evidence → DB → Twin → BOM → console, for five families, with the count "
        "and identity of what arrives asserted at each hop. `SKIPPED` is not a pass and fails the "
        "family's completeness.",
        "",
        "| Family | What produced its input | Hops | Verdict |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['family']}` | {row['transport']} | "
                     f"{row['stages_passed']}/{row['stages_total']} | **{row['verdict']}** |")

    lines += ["", "## Hop by hop", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['family']}` — {row['verdict']}")
        lines.append("")
        lines.append("| Hop | Verdict | What was asserted |")
        lines.append("|---|---|---|")
        for stage in row["stages"]:
            detail = str(stage["detail"]).replace("|", "/")
            lines.append(f"| `{stage['stage']}` | **{stage['verdict']}** | {detail} |")
        lines.append("")

    if report.get("defects"):
        lines += ["## Defects this path exposes", "",
                  "Found while walking the path, reported rather than fixed here. They do not change "
                  "the verdicts above, and they are not the reason the path passes.", "",
                  "| Family | Defect | Asset | Detail |", "|---|---|---|---|"]
        for defect in report["defects"]:
            lines.append(f"| `{defect['family']}` | `{defect['id']}` | `{defect['asset_id']}` | "
                         f"{defect['detail']} |")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "A passing row means a payload of that family's shape survives every hop with its identity "
        "and its facts intact. It does not mean the collector was run against a bank's network, and "
        "it is not a substitute for the per-family qualification a deployment needs.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="The five-family golden path, measured.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--only", help="comma-separated families to run")
    parser.add_argument("--min-families", type=int, default=0,
                        help="exit non-zero when fewer than this many families pass")
    args = parser.parse_args(argv)

    only = [name.strip() for name in args.only.split(",") if name.strip()] if args.only else None
    report = measure(only)

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
            failed = f" (failed: {', '.join(row['failed_stages'])})" if row["failed_stages"] else ""
            print(f"{row['verdict']:<8} {row['family']:<12} "
                  f"{row['stages_passed']}/{row['stages_total']} hops{failed}")
        print(f"\n{report['families_passed']}/{report['families']} families passed, "
              f"{report['stages_passed']}/{report['stages_total']} hops")
    return 0 if report["families_passed"] >= args.min_families else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

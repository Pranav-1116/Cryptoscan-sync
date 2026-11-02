#!/usr/bin/env python3
"""Guide 136 — the four things 135 still could not answer, measured.

Guide 135 closed the range, restore and licence-state gaps and ended with a
limits list. Four of those limits were not footnotes but missing capability, and
this artifact measures the code that closes them:

* **Durability (item 8, the half code can state).** ``storage_topology`` decides
  whether two sites can be called highly available — sharing a region is a
  refusal, and a required axis nobody declared is a refusal too, because an
  unknown failure domain is not a second one. ``ReplicatedStore`` writes every
  object to every site, reads each write back and compares digests, and
  acknowledges only on a verified quorum. The artifact manifest now carries both
  the placement verdict and which sites verified the object.
* **Archive intake (item 17).** ``archive_guard`` refuses traversal, absolute
  paths, device nodes and links out of the root *before* anything is expanded, and
  ``binary_scan`` never parses a refused member. A hostile archive is a refusal,
  not a budget: no amount of headroom makes ``../../etc/passwd`` safe.
* **Licence obligations (item 12, the part a licence inventory cannot answer).**
  ``license_obligations`` turns a licence plus a *distribution model* into duties
  with clause citations — the same GPL component obliges nothing used internally
  and demands source when shipped. It returns ``NO_ACTION``/``REVIEW``/
  ``NEEDS_LEGAL`` and never "compliant".
* **Deployment evidence (item 6).** ``deployment_collectors`` reads a pod listing
  and a CMDB register into observations. A container the runtime names only by tag
  yields no observation, and a workload two applications claim is attributed to
  neither. This is the difference between "the SBOM lists it" and "somebody saw it
  running".
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
import tempfile
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.sbom-availability-guide/1"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "devsecops"), str(SERVICES / "container_scanner"),
                  str(SERVICES / "universal_crypto"), str(SERVICES / "governance"),
                  str(ROOT / "shared" / "shared_models"), str(ROOT / "shared" / "shared_config"),
                  str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from devsecops import (archive_guard, artifact_store, binary_scan,  # noqa: PLC0415
                           deployment_collectors, license_obligations, sbom_evidence,
                           storage_topology)

    return {"topology": storage_topology, "store": artifact_store, "guard": archive_guard,
            "binary": binary_scan, "obligations": license_obligations,
            "collect": deployment_collectors, "se": sbom_evidence}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# 1. failure domains
# --------------------------------------------------------------------------- #

#: (provider, region, zone) pairs and whether they may be called separate.
DOMAIN_CASES: tuple[tuple[str, tuple[str, str, str], tuple[str, str, str], str], ...] = (
    ("same region, other zone", ("aws", "eu-west-1", "a"), ("aws", "eu-west-1", "b"), "REFUSE"),
    ("other region", ("aws", "eu-west-1", "a"), ("aws", "eu-central-1", "a"), "ALLOW"),
    ("other provider, same region", ("aws", "eu-west-1", "a"), ("azure", "eu-west-1", "a"),
     "REFUSE"),
    ("other region, same provider", ("aws", "eu-west-1", "a"), ("aws", "us-east-1", "b"),
     "ALLOW"),
)


def row_failure_domains(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    topology = modules["topology"]
    probes = []

    for label, left, right, expected in DOMAIN_CASES:
        sites = [topology.StoreSite(name="primary", provider=left[0], region=left[1], zone=left[2]),
                 topology.StoreSite(name="replica", provider=right[0], region=right[1],
                                    zone=right[2])]
        verdict = topology.placement(sites)
        probes.append(_probe(
            f"placement-{label.replace(' ', '-')}",
            verdict["verdict"] == expected,
            f"{verdict['verdict']} — {verdict['statement']}"))

    one = topology.placement([topology.StoreSite(name="primary", provider="aws",
                                                region="eu-west-1")])
    probes.append(_probe(
        "one-site-is-not-redundant",
        one["verdict"] == "REFUSE" and "at least 2 are required" in one["statement"],
        one["statement"]))

    no_zone = topology.placement(
        [topology.StoreSite(name="a", provider="aws", region="eu-west-1"),
         topology.StoreSite(name="b", provider="aws", region="eu-central-1")],
        require=("zone",))
    probes.append(_probe(
        "an-undeclared-axis-is-not-separation",
        no_zone["verdict"] == "REFUSE" and "cannot be shown" in no_zone["statement"],
        no_zone["statement"]))

    undeclared = topology.topology_from_env({})
    probes.append(_probe(
        "undeclared-topology-is-a-state-not-a-pass",
        undeclared["verdict"] == "UNDECLARED" and undeclared["declared"] is False,
        undeclared["statement"]))

    invalid = topology.topology_from_env({"SBOM_STORAGE_SITES": "{not json"})
    probes.append(_probe("invalid-topology-is-refused", invalid["verdict"] == "INVALID",
                         invalid["statement"]))

    declared = topology.topology_from_env({"SBOM_STORAGE_SITES": json.dumps([
        {"name": "primary", "provider": "aws", "region": "eu-west-1"},
        {"name": "dr", "provider": "aws", "region": "eu-central-1"}])})
    probes.append(_probe("a-declared-cross-region-pair-passes",
                         declared["verdict"] == "ALLOW" and declared["declared"] is True,
                         declared["statement"]))

    return {"id": "storage_failure_domains",
            "question": "can the platform tell a replica from a second copy in the same room?",
            "phase": "8", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. replicated writes
# --------------------------------------------------------------------------- #


class _Memory:
    """A site that can be told to lose a write or corrupt a read-back."""

    def __init__(self, *, corrupt: bool = False, fail: bool = False):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, dict] = {}
        self.corrupt = corrupt
        self.fail = fail

    def put(self, key, blob):
        if self.fail:
            raise OSError("volume is gone")
        self.blobs[key] = blob + (b"tampered" if self.corrupt else b"")

    def put_manifest(self, key, manifest):
        if self.fail:
            raise OSError("volume is gone")
        self.manifests[key] = manifest

    def get(self, key):
        return self.blobs[key]

    def delete(self, key):
        self.blobs.pop(key, None)
        self.manifests.pop(key, None)

    def list_manifests(self):
        return list(self.manifests.values())


def row_replicated_writes(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    topology = modules["topology"]
    probes = []
    primary_site = topology.StoreSite(name="primary", provider="aws", region="eu-west-1")
    dr_site = topology.StoreSite(name="dr", provider="aws", region="eu-central-1")

    store = topology.ReplicatedStore(sites=(primary_site, dr_site),
                                     backends={"primary": _Memory(), "dr": _Memory()})
    put = store.put("blob", b"evidence")
    probes.append(_probe(
        "every-site-verifies-its-own-copy",
        put["acknowledged"] and sorted(put["verified"]) == ["dr", "primary"]
        and put["sha256"],
        f"verified on {', '.join(sorted(put['verified']))}; quorum {put['quorum']}"))

    healthy = store.health()
    probes.append(_probe("health-is-reported-per-site", healthy["verdict"] == "HEALTHY",
                         healthy["statement"]))

    corrupt = topology.ReplicatedStore(
        sites=(primary_site, dr_site),
        backends={"primary": _Memory(), "dr": _Memory(corrupt=True)})
    refused = False
    try:
        corrupt.put("blob", b"evidence")
    except IOError:
        refused = True
    degraded = corrupt.health()
    probes.append(_probe(
        "a-corrupted-read-back-is-a-failed-site",
        refused and degraded["verdict"] == "DEGRADED" and "dr" in degraded["degraded"],
        f"write refused below quorum; {degraded['statement']}"))

    three = topology.ReplicatedStore(
        sites=(primary_site, dr_site, topology.StoreSite(name="cold", provider="azure",
                                                         region="us-east-1")),
        backends={"primary": _Memory(), "dr": _Memory(), "cold": _Memory(fail=True)})
    survived = three.put("blob", b"evidence")
    probes.append(_probe(
        "a-quorum-survives-one-dead-site-and-says-so",
        survived["acknowledged"] and three.health()["verdict"] == "DEGRADED",
        f"quorum {survived['quorum']} of {len(survived['written']) + len(survived['failed'])} "
        f"sites; {three.health()['statement']}"))

    two = topology.ReplicatedStore(sites=(primary_site, dr_site),
                                   backends={"primary": _Memory(), "dr": _Memory(fail=True)})
    below = False
    try:
        two.put("blob", b"evidence")
    except IOError as exc:
        below = "below the quorum" in str(exc)
    probes.append(_probe("one-copy-out-of-two-is-not-a-quorum", below,
                         "two-site write with one dead site raises instead of acknowledging"))

    # the artifact manifest carries the placement and the replication result
    saved = {key: os.environ.get(key) for key in (
        "ENVIRONMENT", "SBOM_STORAGE_DIR", "SBOM_STORAGE_BACKUP_DIR", "SBOM_RETENTION_DAYS",
        "SBOM_STORAGE_REPLICA_DIRS", "SBOM_STORAGE_SITES")}
    with tempfile.TemporaryDirectory() as tmp:
        try:
            os.environ.update({
                "ENVIRONMENT": "production",
                "SBOM_STORAGE_DIR": os.path.join(tmp, "primary"),
                "SBOM_STORAGE_BACKUP_DIR": os.path.join(tmp, "backup"),
                "SBOM_RETENTION_DAYS": "365",
                "SBOM_STORAGE_REPLICA_DIRS": f"dr={os.path.join(tmp, 'dr')}",
                "SBOM_STORAGE_SITES": json.dumps([
                    {"name": "primary", "provider": "aws", "region": "eu-west-1"},
                    {"name": "dr", "provider": "aws", "region": "eu-central-1"}]),
            })
            bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
                   "components": [{"name": "openssl", "version": "3.0.13"}]}
            stored = modules["store"].store_binary_artifact(
                scan={"target": "/opt/bank/app", "result_state": "COMPLETE"},
                result={"packages": [{"name": "openssl", "version": "3.0.13", "manager": "deb"}],
                        "binaries": [], "libraries": []},
                bom=bom, cbom={"components": []}, created_by="guide-136",
                secret=(None, "unsigned"))
            storage = stored["manifest"]["storage"]
            replica_dir = os.path.join(tmp, "dr")
            probes.append(_probe(
                "the-manifest-records-the-placement-verdict",
                storage["topology"]["verdict"] == "ALLOW",
                storage["topology"]["statement"]))
            probes.append(_probe(
                "the-manifest-records-which-sites-verified-the-object",
                storage["replication"]["verdict"] == "REPLICATED"
                and len(storage["replication"]["verified"]) >= 2,
                storage["replication"]["statement"]))
            probes.append(_probe(
                "the-object-really-exists-at-the-second-site",
                len([name for name in os.listdir(replica_dir) if name.endswith(".enc")]) >= 2,
                f"{len(os.listdir(replica_dir))} object(s) written to the replica root"))

            os.environ["SBOM_STORAGE_SITES"] = json.dumps([
                {"name": "primary", "provider": "aws", "region": "eu-west-1"},
                {"name": "dr", "provider": "aws", "region": "eu-west-1"}])
            same_region = modules["store"].store_binary_artifact(
                scan={"target": "/opt/bank/app2"}, result={"packages": []}, bom=bom,
                cbom={"components": []}, created_by="guide-136", secret=(None, "unsigned"))
            probes.append(_probe(
                "a-same-region-replica-is-refused-on-the-manifest",
                same_region["manifest"]["storage"]["topology"]["verdict"] == "REFUSE",
                same_region["manifest"]["storage"]["topology"]["statement"]))

            os.environ.pop("SBOM_STORAGE_SITES")
            undeclared = modules["store"].store_binary_artifact(
                scan={"target": "/opt/bank/app3"}, result={"packages": []}, bom=bom,
                cbom={"components": []}, created_by="guide-136", secret=(None, "unsigned"))
            probes.append(_probe(
                "an-undeclared-replica-domain-is-not-called-separate",
                undeclared["manifest"]["storage"]["topology"]["verdict"] == "UNDECLARED",
                undeclared["manifest"]["storage"]["topology"]["statement"]))
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    return {"id": "replicated_writes",
            "question": "is a copy a copy, or only a write that returned 200?",
            "phase": "8", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. archive intake
# --------------------------------------------------------------------------- #

#: (label, member name, expected verdict, why)
GUARD_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("traversal", "../../etc/passwd", "REFUSE", "a member may not escape the root"),
    ("nested traversal", "app/../../../etc/shadow", "REFUSE", "the same rule, one level down"),
    ("absolute path", "/etc/passwd", "REFUSE", "an absolute member ignores the root entirely"),
    ("windows drive", "C:\\windows\\system32\\x.dll", "REFUSE", "the same escape on another host"),
    ("backslash traversal", "app\\..\\..\\win.ini", "REFUSE", "separators are normalised, then judged"),
    ("overlong name", "a/" + "b" * 4096, "REFUSE", "a name longer than any filesystem's limit"),
    ("escape sequence", "app/\x1b[2J.sh", "REFUSE", "a control character is not a filename"),
    ("ordinary member", "app/lib/libssl.so.3", "ALLOW", "nothing to refuse"),
    ("nested member", "app/share/doc/README", "ALLOW", "depth is not a problem"),
)


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in members:
            archive.writestr(name, blob)
    return buf.getvalue()


def _tar(entries: list[tuple[str, bytes | None, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, payload, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = str(payload or b"", "utf-8")
                archive.addfile(info)
            elif payload is None:
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def row_archive_intake(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    guard = modules["guard"]
    probes = []

    for label, name, expected, why in GUARD_CASES:
        members = [(name, b"payload")]
        # a zip truncates at a NUL, so the filler would collide with the member
        # under test and the duplicate rule would answer instead
        if "app/ok" not in name:
            members.append(("app/ok", b"ok"))
        verdict = guard.from_zip(_zip(members))
        probes.append(_probe(
            f"guard-{label.replace(' ', '-')}", verdict["verdict"] == expected,
            f"{verdict['verdict']} — {verdict['statement']}"))

    # a zip truncates its own member names at a NUL, so this check is exercised on
    # the descriptor path the tar reader and the cpio reader both feed
    nul = guard.assess_members([{"name": "app/ok\x00.sh", "size": 1}])
    probes.append(_probe("a-nul-in-a-member-name-is-refused",
                         nul["verdict"] == "REFUSE" and "NUL byte" in nul["statement"],
                         nul["statement"]))

    escape = guard.from_tar(_tar([("app/link", b"../../etc/shadow", tarfile.SYMTYPE)]))
    probes.append(_probe("a-symlink-out-of-the-root-is-refused",
                         escape["verdict"] == "REFUSE" and "links outside" in escape["statement"],
                         escape["statement"]))

    device = guard.from_tar(_tar([("dev/mem", None, tarfile.CHRTYPE)]))
    probes.append(_probe("a-device-node-is-refused",
                         device["verdict"] == "REFUSE" and "device" in device["statement"],
                         device["statement"]))

    fifo = guard.from_tar(_tar([("run/pipe", None, tarfile.FIFOTYPE)]))
    probes.append(_probe("a-fifo-is-refused", fifo["verdict"] == "REFUSE", fifo["statement"]))

    bomb = guard.assess_members([{"name": "bomb.tar", "size": 10_000_000,
                                  "compressed_size": 100}])
    probes.append(_probe("a-compression-bomb-ratio-is-refused",
                         bomb["verdict"] == "REFUSE" and "ratio limit" in bomb["statement"],
                         bomb["statement"]))

    duplicate = guard.assess_members([{"name": "a/index", "size": 1},
                                      {"name": "a/index", "size": 2}])
    probes.append(_probe("a-duplicate-member-is-refused", duplicate["verdict"] == "REFUSE",
                         duplicate["statement"]))

    clean = guard.from_tar(_tar([("app/bin/openssl", b"\x7fELF" + b"\x00" * 64,
                                  tarfile.REGTYPE)]))
    probes.append(_probe("a-clean-archive-passes", clean["verdict"] == "ALLOW",
                         clean["statement"]))

    unknown = guard.inspect(b"\x7fELF" + b"\x00" * 512)
    probes.append(_probe("an-unrecognised-format-is-not-assumed-fine",
                         unknown["verdict"] == "REFUSE", unknown["statement"]))

    # the scanner consumes the guard: a refused member is never parsed
    hostile_zip = _zip([("../../etc/passwd", b"root:x:0:0"), ("app/ok", b"fine")])
    explored = modules["binary"].explore_container(hostile_zip, "zip", depth=0, prefix="",
                                                  parsed=[])
    reasons = [row for row in explored["refused"] if row.get("member_count")]
    probes.append(_probe(
        "the-scanner-never-parses-a-refused-member",
        explored.get("archive_guard", {}).get("verdict") == "REFUSE" and reasons,
        f"archive_guard={explored.get('archive_guard', {}).get('verdict')}; "
        f"{reasons[0]['reason'] if reasons else 'no refusal recorded'}"))

    clean_explored = modules["binary"].explore_container(
        _zip([("app/lib/libssl.so.3", b"\x7fELF" + b"\x00" * 64)]), "zip", depth=0, prefix="",
        parsed=[])
    probes.append(_probe(
        "a-clean-container-carries-an-allowing-guard",
        clean_explored.get("archive_guard", {}).get("verdict") == "ALLOW",
        clean_explored.get("archive_guard", {}).get("statement", "no guard recorded")))

    return {"id": "archive_intake",
            "question": "may this archive's members be expanded at all?",
            "phase": "17", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. licence obligations by distribution model
# --------------------------------------------------------------------------- #

#: (licence, model, modified, duties that must be triggered, duties that must not)
OBLIGATION_CASES: tuple[tuple[str, str, bool, frozenset[str], frozenset[str]], ...] = (
    ("MIT", "INTERNAL", False, frozenset({"PATENT_GRANT"}),
     frozenset({"NOTICE_FILE", "NOTICE_PRESERVATION"})),
    ("MIT", "BINARY_SHIPPED", False,
     frozenset({"ATTRIBUTION", "NOTICE_FILE", "NOTICE_PRESERVATION", "PATENT_GRANT"}),
     frozenset({"SOURCE_DISCLOSURE", "DERIVATIVE_SCOPE"})),
    ("Apache-2.0", "BINARY_SHIPPED", False,
     frozenset({"ATTRIBUTION", "NOTICE_FILE", "NOTICE_PRESERVATION", "PATENT_GRANT"}),
     frozenset({"MODIFICATION_DISCLOSURE"})),
    ("Apache-2.0", "BINARY_SHIPPED", True, frozenset({"MODIFICATION_DISCLOSURE"}),
     frozenset({"SOURCE_DISCLOSURE"})),
    ("GPL-3.0-only", "INTERNAL", False, frozenset(), frozenset({"SOURCE_DISCLOSURE"})),
    ("GPL-3.0-only", "BINARY_SHIPPED", False,
     frozenset({"SOURCE_DISCLOSURE", "DERIVATIVE_SCOPE", "NOTICE_FILE"}),
     frozenset({"NETWORK_SOURCE_OFFER"})),
    ("GPL-3.0-only", "BINARY_SHIPPED", True, frozenset({"MODIFICATION_DISCLOSURE"}),
     frozenset({"NETWORK_SOURCE_OFFER"})),
    ("GPL-3.0-only", "SAAS", False, frozenset({"DERIVATIVE_SCOPE"}),
     frozenset({"SOURCE_DISCLOSURE"})),
    ("AGPL-3.0-only", "SAAS", False, frozenset({"NETWORK_SOURCE_OFFER", "DERIVATIVE_SCOPE"}),
     frozenset()),
    ("AGPL-3.0-only", "INTERNAL", False, frozenset({"DERIVATIVE_SCOPE"}),
     frozenset({"NETWORK_SOURCE_OFFER"})),
    ("LGPL-2.1-only", "BINARY_SHIPPED", True, frozenset({"RELINKING", "MODIFICATION_DISCLOSURE"}),
     frozenset({"NETWORK_SOURCE_OFFER"})),
    ("MPL-2.0", "BINARY_SHIPPED", True, frozenset({"SOURCE_DISCLOSURE", "DERIVATIVE_SCOPE"}),
     frozenset({"NETWORK_SOURCE_OFFER"})),
    ("CC0-1.0", "BINARY_SHIPPED", False, frozenset({"NO_OBLIGATION"}),
     frozenset({"ATTRIBUTION", "SOURCE_DISCLOSURE"})),
)


def row_licence_obligations(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    obligations = modules["obligations"]
    probes = []

    for licence, model, modified, expected, forbidden in OBLIGATION_CASES:
        result = obligations.obligations_for(
            licence, family=obligations.family_for_licence(licence), model=model,
            modified=modified)
        open_duties = set(result["open"])
        label = f"{licence}-{model}" + ("-modified" if modified else "")
        probes.append(_probe(
            f"duties-{label}", expected <= open_duties and not (forbidden & open_duties),
            f"{sorted(open_duties)} — {result['statement']}"))

    unknown = obligations.obligations_for("", family="UNKNOWN", model="INTERNAL")
    probes.append(_probe("an-unidentified-licence-needs-legal",
                         unknown["verdict"] == "NEEDS_LEGAL"
                         and unknown["open"] == ["TERMS_UNKNOWN"],
                         unknown["statement"]))

    nc = obligations.obligations_for("CC-BY-NC-4.0", family="NON_COMMERCIAL", model="BINARY_SHIPPED")
    probes.append(_probe("a-non-commercial-licence-is-flagged-in-every-model",
                         nc["verdict"] == "NEEDS_LEGAL"
                         and "NC_USE_RESTRICTION" in nc["open"], nc["statement"]))

    proprietary = obligations.obligations_for("LicenseRef-Acme-EULA", family="PROPRIETARY",
                                              model="BINARY_SHIPPED")
    probes.append(_probe("a-proprietary-licence-is-not-answered-by-this-table",
                         proprietary["verdict"] == "NEEDS_LEGAL"
                         and "COMMERCIAL_TERMS" in proprietary["open"],
                         proprietary["statement"]))

    verdicts = {obligations.obligations_for(
        licence, family=obligations.family_for_licence(licence), model=model)["verdict"]
        for model in obligations.DISTRIBUTION_MODELS
        for licence in ("MIT", "Apache-2.0", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-3.0",
                        "MPL-2.0", "CC0-1.0", "", "LicenseRef-X")}
    probes.append(_probe(
        "the-engine-never-returns-compliant",
        verdicts <= {"NO_ACTION", "REVIEW", "NEEDS_LEGAL"},
        ", ".join(sorted(verdicts))))

    every_obligation_cites = all(
        row.title and row.cite for row in obligations.OBLIGATIONS.values())
    probes.append(_probe("every-duty-cites-a-clause", every_obligation_cites,
                         f"{len(obligations.OBLIGATIONS)} duties, each with a title and a cite"))

    portfolio = obligations.portfolio_obligations([
        {"name": "requests", "licence": "Apache-2.0"},
        {"name": "openssl", "licence": "Apache-2.0"},
        {"name": "busybox", "licence": "GPL-2.0-only", "modified": True},
        {"name": "mystery", "licence": ""},
    ], model="BINARY_SHIPPED")
    probes.append(_probe(
        "a-portfolio-groups-duties-across-components",
        portfolio["counts"].get("SOURCE_DISCLOSURE") == 1
        and portfolio["unknown_components"] == ["mystery"]
        and portfolio["verdict"] == "NEEDS_LEGAL",
        portfolio["statement"]))

    router = (ROOT / "services" / "api" / "api" / "routers" / "devsecops.py").read_text(
        encoding="utf-8")
    probes.append(_probe(
        "the-api-exposes-obligations-beside-the-licence-inventory",
        '/sbom/obligations' in router and "portfolio_obligations(" in router,
        "/sbom/obligations answers what the model obliges; /sbom/license answers what is in "
        "the document"))

    return {"id": "licence_obligations",
            "question": "what does shipping this component make the bank do?",
            "phase": "12", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. deployment evidence
# --------------------------------------------------------------------------- #


def _pod(*, name="api-1", namespace="payments", kind="Pod",
         image="ghcr.io/bank/api:2026.11.02", image_id=None, running=True):
    state = {"running": {}} if running else {"waiting": {"reason": "ImagePullBackOff"}}
    return {"kind": kind, "metadata": {"namespace": namespace, "name": name},
            "spec": {"containers": [{"name": "api", "image": image}]},
            "status": {"containerStatuses": [
                {"name": "api",
                 "imageID": image_id if image_id is not None
                 else f"docker-pullable://{image.split(':')[0]}@{DIGEST}",
                 "state": state}]}}


def row_deployment_evidence(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    collect = modules["collect"]
    se = modules["se"]
    probes = []

    collected = collect.observations_from_kubernetes({"items": [_pod()]}, observed_at=as_of,
                                                     cluster="prod-eu")
    probes.append(_probe(
        "a-running-container-becomes-an-observation",
        len(collected["observations"]) == 1
        and collected["observations"][0]["artifact"]["digest"] == DIGEST,
        collected["statement"]))

    tag_only = collect.observations_from_kubernetes(
        {"items": [_pod(image="ghcr.io/bank/api:latest",
                        image_id="docker-pullable://ghcr.io/bank/api:latest")]},
        observed_at=as_of)
    probes.append(_probe(
        "a-tag-only-image-yields-no-observation",
        tag_only["observations"] == [] and tag_only["refused"]
        and "no immutable identity" in tag_only["refused"][0]["reason"],
        tag_only["statement"]))

    waiting = collect.observations_from_kubernetes({"items": [_pod(running=False)]},
                                                   observed_at=as_of)
    probes.append(_probe("a-crashlooping-container-is-not-deployed",
                         waiting["observations"] == []
                         and "not in a running state" in waiting["skipped"][0]["reason"],
                         waiting["statement"]))

    configmap = collect.observations_from_kubernetes({"items": [_pod(kind="ConfigMap")]},
                                                     observed_at=as_of)
    probes.append(_probe("a-configmap-is-not-a-workload",
                         configmap["observations"] == []
                         and "does not run containers" in configmap["skipped"][0]["reason"],
                         configmap["statement"]))

    register = collect.register_from_cmdb({"applications": [
        {"name": "payments-api", "business_system": "Card Processing", "owner": "Payments",
         "criticality": "Tier 1", "workloads": ["pod/payments/api-1"]}]})
    probes.append(_probe("the-register-attributes-a-workload-to-a-business-system",
                         register["by_workload"]["pod/payments/api-1"] == ["payments-api"],
                         register["statement"]))

    conflict = collect.register_from_cmdb({"applications": [
        {"name": "a", "workloads": ["pod/payments/api-1"]},
        {"name": "b", "workloads": ["pod/payments/api-1"]}]})
    probes.append(_probe("a-workload-claimed-twice-is-a-conflict",
                         conflict["conflicts"]
                         and "more than one application" in conflict["statement"],
                         conflict["statement"]))

    def sbom(digest: str):
        return se.SbomRecord(sbom_id="SBOM-136",
                             artifact=se.ArtifactIdentity("ghcr.io/bank/api", digest),
                             components=({"name": "openssl", "version": "3.0.13"},))

    deployed = collect.correlate([sbom(DIGEST)], collected["observations"], register=register)
    probes.append(_probe(
        "a-matching-digest-is-present-in-deployment",
        deployed["rows"][0]["state"] == "PRESENT_IN_DEPLOYMENT"
        and deployed["rows"][0]["business_systems"] == ["Card Processing"],
        deployed["rows"][0]["state"] + "; " + deployed["statement"]))

    absent = collect.correlate([sbom(OTHER_DIGEST)], collected["observations"])
    probes.append(_probe(
        "an-unobserved-digest-stops-at-the-artifact",
        absent["rows"][0]["state"] == "PRESENT_IN_ARTIFACT" and absent["deployed"] == 0,
        absent["rows"][0]["state"]))

    document_only = collect.correlate(
        [se.SbomRecord(sbom_id="SBOM-136b", artifact=None, components=({"name": "openssl"},))],
        collected["observations"])
    probes.append(_probe(
        "an-unbound-document-is-never-called-deployed",
        document_only["rows"][0]["state"] == "PRESENT_IN_SBOM_ONLY",
        document_only["rows"][0]["state"]))

    blocked = collect.correlate([sbom(DIGEST)], collected["observations"], register=conflict)
    probes.append(_probe(
        "a-conflicted-workload-is-attributed-to-neither-application",
        blocked["rows"][0]["applications"] == []
        and blocked["rows"][0]["attribution"] == "CONFLICT",
        blocked["statement"]))

    return {"id": "deployment_evidence",
            "question": "is this component in the SBOM, or in production?",
            "phase": "6", "probes": probes}


ROWS = (row_failure_domains, row_replicated_writes, row_archive_intake,
        row_licence_obligations, row_deployment_evidence)


# --------------------------------------------------------------------------- #
# measure + render
# --------------------------------------------------------------------------- #


def measure(as_of: date | None = None) -> dict[str, Any]:
    as_of = as_of or datetime.now(timezone.utc).date()
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules, as_of)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = PARTIAL
        else:
            verdict = FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "domain_cases": len(DOMAIN_CASES),
        "guard_cases": len(GUARD_CASES),
        "obligation_cases": len(OBLIGATION_CASES),
        "rows": rows,
        "limits": [
            "the topology check compares what an operator *declared*. It cannot see that two "
            "providers' control planes share a fibre path or one IAM administrator, so "
            "'separate on region' is a statement about the declared axes and nothing more",
            "the replicated writer verifies bytes, not availability: a write that reached a "
            "quorum says the copies exist now, not that a site will answer during an incident",
            "archive_guard judges the member list before expansion. It refuses what it can "
            "recognise as hostile; an archive format it does not model is reported as "
            "unrecognised rather than declared safe",
            "licence obligations are a checklist with clause citations, not legal advice. "
            "Derivative-work questions, linking questions and the acceptability of a licence "
            "are counsel's call, which is why the verdict tops out at NEEDS_LEGAL",
            "the deployment collector needs a truth source it is given. Without a cluster "
            "listing or a CMDB export it observes nothing, and 'no observation' is not "
            "'not deployed' — it is 'nobody looked'",
            "correlation matches artifact digests. A workload running an image the registry "
            "has no SBOM for produces no rows at all, which is a gap in the inventory, not a "
            "clean result",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Four questions the last guide could not answer",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 135 ended with a list of what it had not proven. Four of those entries were "
        "not footnotes but missing capability, and this artifact is where each one is "
        "measured:",
        "",
        "1. **Failure domains.** An object store in the same region as the primary is not a "
        "backup. `storage_topology` refuses a pair that shares a required axis — and refuses "
        "one that never declared the axis, because an unknown domain is not a second one.",
        "2. **Replicated writes.** `ReplicatedStore` writes every object to every site, reads "
        "each write back and compares digests, and only acknowledges on a verified quorum. "
        "The artifact manifest now carries both the placement verdict and which sites "
        "verified the bytes.",
        "3. **Archive intake.** `archive_guard` refuses traversal, device nodes, fifos and "
        "links out of the root *before* expansion, and `binary_scan` never parses a refused "
        "member. A hostile archive is a refusal, not a budget.",
        "4. **Obligations and deployment.** `license_obligations` turns a licence plus a "
        "distribution model into cited duties, and `deployment_collectors` turns a pod "
        "listing and a CMDB register into observations that stop the moment the runtime only "
        "offers a tag.",
        "",
        f"The decision tables behind these probes are {report['domain_cases']} placement "
        f"cases, {report['guard_cases']} archive cases and {report['obligation_cases']} "
        "licence-model cases.",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (review item {row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--as-of", type=date.fromisoformat, default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure(args.as_of)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail",
          file=sys.stderr)
    if not args.check:
        return 0
    if counts[FAIL]:
        return 2
    if counts[PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

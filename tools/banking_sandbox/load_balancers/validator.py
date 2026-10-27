"""Independent LB input integrity and hidden-harness result comparisons; never a collector."""

from collections import Counter
import json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from tools.banking_sandbox.common import records, inside, open_estate
from tools.banking_sandbox.documents import validators
from tools.banking_sandbox.load_balancers.catalog import SCENARIOS, ROLES


def validate_bank(public, bank, full_schemas=False):
    folder = public / "load_balancers" / bank
    if not folder.exists():
        return {"banks": 0, "cases": 0, "crypto_hops": 0, "bom_documents": 0}
    inventory = json.loads((folder / "inventory.json").read_text())
    nodes = {n["lb_id"]: n for n in inventory["nodes"]}
    apps = {a["app_id"] for a in records(public / "applications" / f"{bank}.jsonl")}
    systems = {a["system_id"] for a in records(public / "systems" / f"{bank}.jsonl")}
    hsms = {a["hsm_id"] for a in records(public / "hsm" / f"{bank}.jsonl")}
    keys = {r["key_reference"]: r for r in records(folder / "keys.jsonl")}
    certs = {c["certificate_id"]: c for c in records(folder / "certificates.jsonl")}
    ev = {e["evidence_id"]: e for e in records(folder / "evidence.jsonl")}
    cases = list(records(folder / "cases.jsonl"))
    hops = {h["hop_id"]: h for h in records(folder / "hops.jsonl")}
    if len(cases) != 35 or {c["scenario"] for c in cases} != set(SCENARIOS):
        raise ValueError("LB scenario coverage")
    if len({c["case_id"] for c in cases}) != 35:
        raise ValueError("duplicate LB case")
    for n in nodes.values():
        if (
            n["bank_id"] != bank
            or n["role"] not in ROLES
            or n["system_id"] not in systems
            or not set(n["backend_targets"]) <= apps
        ):
            raise ValueError("LB node references")
        if not set(n["certificate_ids"]) <= certs.keys():
            raise ValueError("LB certificate reference")
        for ref in n["config_refs"]:
            inside(public, ref).read_bytes()
    for cluster in inventory["clusters"]:
        if not set(cluster["members"]) <= nodes.keys() or len(set(cluster["members"])) != 2:
            raise ValueError("LB cluster references")
        for state in cluster["member_states"]:
            if state["certificate_id"] not in certs:
                raise ValueError("HA certificate missing")
    for c in certs.values():
        raw = inside(public, c["pem_ref"]).read_bytes()
        cert = x509.load_pem_x509_certificate(raw)
        if b"PRIVATE KEY" in raw or cert.fingerprint(hashes.SHA256()).hex() != c["sha256"]:
            raise ValueError("LB certificate fingerprint")
        if cert.signature_algorithm_oid.dotted_string != "1.3.101.112" or c["signature_algorithm"] != "Ed25519":
            raise ValueError("LB signature metadata")
        if (
            cert.not_valid_before_utc.isoformat() != c["not_before"]
            or cert.not_valid_after_utc.isoformat() != c["not_after"]
        ):
            raise ValueError("LB certificate validity metadata")
        key = cert.public_key()
        if (
            key.key_size != c["key_size"]
            or ("RSA" if isinstance(key, rsa.RSAPublicKey) else "EC") != c["public_key_algorithm"]
        ):
            raise ValueError("LB certificate key metadata")
        if not isinstance(key, rsa.RSAPublicKey) and key.curve.name != c["curve"]:
            raise ValueError("LB certificate curve")
        if [c.value for c in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value] != c["san"]:
            raise ValueError("LB SAN mismatch")
        chain = [x509.load_pem_x509_certificate(inside(public, r).read_bytes()) for r in c["chain_refs"]]
        chain[0].public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        for child, parent in zip(chain, chain[1:]):
            parent.public_key().verify(child.signature, child.tbs_certificate_bytes)
        if c["private_key_exported"] or not c["private_key_reference"].startswith(("LB-KEY-", "HSM-KEY-")):
            raise ValueError("LB key export policy")
    for k in keys.values():
        if k["hsm_id"] not in hsms or k["certificate_id"] not in certs or k["lb_id"] not in nodes:
            raise ValueError("LB HSM relationship")
        cert = certs[k["certificate_id"]]
        if (
            cert["private_key_reference"] != k["key_reference"]
            or cert["public_key_algorithm"] != k["algorithm"]
            or cert["key_size"] != k["key_size"]
        ):
            raise ValueError("LB HSM key parameters")
    assets = set()
    for c in cases:
        if c["lb_id"] not in nodes or not set(c["hop_ids"]) <= hops.keys():
            raise ValueError("LB hop reference")
        sessions = [hops[i] for i in c["hop_ids"] if hops[i]["transport"] == "TLS"]
        if c["listener"]["mode"] == "PASSTHROUGH":
            if (
                len(sessions) != 1
                or sessions[0]["termination_point"] not in apps
                or c["listener"]["certificate_id"] is not None
            ):
                raise ValueError("passthrough attribution")
        if c["listener"]["mode"] == "RE_ENCRYPTION":
            if len(sessions) < 2 or len({h["crypto_asset_id"] for h in sessions}) != len(sessions):
                raise ValueError("merged TLS hops")
        if not set(c["listener"]["backend_targets"]) <= apps:
            raise ValueError("LB backend reference")
        for domain, cert_id in c["listener"]["sni_certificates"].items():
            if cert_id not in certs or domain not in certs[cert_id]["san"]:
                raise ValueError("SNI certificate mapping")
        for h in [hops[i] for i in c["hop_ids"]]:
            if h["path_id"] != c["path_id"] or h["listener_id"] != c["listener"]["listener_id"]:
                raise ValueError("cross-listener/path attribution")
            if h["bank_id"] != bank or h["lb_id"] != c["lb_id"] or h["backend_target"] not in apps:
                raise ValueError("cross-bank LB hop")
            if h["negotiated"] is not None or h["actual_execution"] or h["evidence_type"] != "CONFIGURED":
                raise ValueError("fixture promoted to observation")
            if not set(h["evidence_ids"]) <= ev.keys():
                raise ValueError("missing hop evidence")
            if h["crypto_asset_id"]:
                if h["crypto_asset_id"] in assets:
                    raise ValueError("shared independent crypto asset")
                assets.add(h["crypto_asset_id"])
                if h["configured"]["certificate_id"] not in certs:
                    raise ValueError("hop certificate missing")
    cdx, spdx = validators()
    checked = 0
    for projection in ("sbom", "cbom"):
        for i, r in enumerate(records(public / projection / (bank + "-loadbalancers.jsonl"))):
            if full_schemas or i < 2:
                (spdx if r.get("format") == "SPDX" else cdx).validate(r["document"])
                checked += 1
    for row in records(public / "cbom" / (bank + "-loadbalancers-stale.jsonl")):
        cdx.validate(row["document"])
        checked += 1
    cbom = {r["target"] for r in records(public / "cbom" / (bank + "-loadbalancers.jsonl"))}
    if cbom != assets:
        raise ValueError("LB CBOM hop attribution")
    return {"banks": 1, "cases": 35, "crypto_hops": len(assets), "bom_documents": checked}


def compare(root, observations):
    """Score supplied actual observations. Does NOT manufacture output from fixture truth."""
    root, _ = open_estate(root)
    expected = {}
    for p in (root / "control/ground_truth").glob("*-loadbalancers.jsonl"):
        for c in records(p):
            for h in c["modeled_sessions"]:
                expected[h["hop_id"]] = {**h, "bank_id": c["bank_id"], "lb_id": c["lb_id"], "case_id": c["case_id"]}
    metrics = {
        key: Counter(correct=0, incorrect=0, unknown=0, missing=0)
        for key in ("attribution", "certificate", "crypto_parameters", "hop_correlation")
    }
    tp = fp = fn = 0
    seen = set()
    failures = 0
    extra = []
    for r in records(Path(observations)):
        hop = r["hop_id"]
        if hop in seen:
            raise ValueError("duplicate hop observation")
        seen.add(hop)
        t = expected.get(hop)
        if t is None:
            extra.append(hop)
            fp += 1
            continue
        if r.get("bank_id") != t["bank_id"] or r.get("case_id") != t["case_id"]:
            raise ValueError("cross-bank/case attribution")
        if r.get("status") not in ("COMPLETE", "PARTIAL", "FAILED", "UNKNOWN"):
            raise ValueError("explicit disposition required")
        if r["status"] != "COMPLETE":
            failures += 1
            fn += 1
            if r.get("safe") or r.get("crypto_absent"):
                raise ValueError("failure promoted to safe/absence")
            for m in metrics.values():
                m["unknown"] += 1
            continue
        if r.get("evidence_type") != "NETWORK_OBSERVED" or not r.get("evidence_id") or not r.get("timestamp"):
            raise ValueError("actual network evidence required")
        fields = {
            "attribution": ("lb_id", "termination_point", "backend_target"),
            "certificate": (
                "certificate_id",
                "certificate_fingerprint_sha256",
                "certificate_public_key_algorithm",
                "certificate_key_size",
                "certificate_curve",
                "certificate_signature_algorithm",
            ),
            "crypto_parameters": ("version", "cipher", "mtls_required"),
            "hop_correlation": ("crypto_asset_id", "path_id"),
        }
        good = True
        for name, keys in fields.items():
            bucket = (
                "missing"
                if any(k not in r for k in keys)
                else "unknown"
                if any(r[k] is None and t[k] is not None for k in keys)
                else "correct"
                if all(r[k] == t[k] for k in keys)
                else "incorrect"
            )
            metrics[name][bucket] += 1
            good &= bucket == "correct"
        if good:
            tp += 1
        else:
            fp += 1
            fn += 1
    missing = set(expected) - seen
    fn += len(missing)
    for m in metrics.values():
        m["missing"] += len(missing)
    return {
        "scope": "SUPPLIED_ACTUAL_LB_NETWORK_RESULTS_VS_HIDDEN_SCENARIO_MODEL",
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "metrics": {
            k: {
                **v,
                "accuracy": v["correct"] / (v["correct"] + v["incorrect"]) if v["correct"] + v["incorrect"] else None,
            }
            for k, v in metrics.items()
        },
        "missing_hops": len(missing),
        "failed_or_partial_or_unknown": failures,
        "unmatched": extra,
        "false_positive_rate": None,
        "false_positive_rate_reason": "No predeclared negative-session population",
        "product_acceptance": False,
        "synthetic": True,
    }

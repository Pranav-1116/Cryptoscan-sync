"""Copy-on-write LB configured drift. No negotiation, signing or traffic claims."""

from copy import deepcopy
import json
from tools.banking_sandbox.common import dump, stream, records


def apply(root):
    changes = []
    for folder in sorted((root / "public/load_balancers").glob("*")):
        if not folder.is_dir():
            continue
        d = json.loads((folder / "drift.json").read_text())
        if not d["enabled"]:
            continue
        cases = list(records(folder / "cases.jsonl"))
        hops = list(records(folder / "hops.jsonl"))
        target = next(h for h in hops if h["hop_id"] == d["target_hop"])
        case = next(c for c in cases if target["hop_id"] in c["hop_ids"])
        certs = {c["certificate_id"]: c for c in records(folder / "certificates.jsonl")}
        previous = deepcopy(target)
        cert = certs[d["certificate_transition"]["to"]]
        target["supported"]["versions"] = d["new_capability"]["versions"]
        target["supported"]["ciphers"] = d["new_capability"]["ciphers"]
        target["configured"]["certificate_id"] = cert["certificate_id"]
        target["timestamp"] = d["changed_at"]
        target["negotiated"] = None
        target["declared_signature_algorithm"] = "SHA-1"
        target["actual_certificate_signature_algorithm"] = cert["signature_algorithm"]
        case["listener"]["certificate_id"] = cert["certificate_id"]
        case["listener"]["private_key_reference"] = cert["private_key_reference"]
        case["listener"]["sni_certificates"] = {name: cert["certificate_id"] for name in case["listener"]["sni"]}
        cfg = root / "public" / case["config_ref"]
        config = json.loads(cfg.read_text())
        config.update(
            sni_certificates=case["listener"]["sni_certificates"],
            certificate_id=cert["certificate_id"],
            private_key_reference=cert["private_key_reference"],
            tls_minimum="TLS1.2",
            tls_maximum="TLS1.3",
            configured_policy=deepcopy(target["supported"]),
            changed_at=d["changed_at"],
        )
        cfg.unlink()
        dump(cfg, config)
        from tools.banking_sandbox.load_balancers.configurations import snippets

        for name, text in snippets(config, cert).items():
            (cfg.parent / name).write_text(text)
        for name, doc in [
            ("envoy.yaml", {"synthetic": True, "tls_context": config}),
            (
                "gateway.yaml",
                {"synthetic": True, "kind": "Gateway", "apply_authorized": False, "listener": case["listener"]},
            ),
        ]:
            p = cfg.parent / name
            p.unlink()
            dump(p, doc)
        for name, rows in [("hops", hops), ("cases", cases)]:
            p = folder / (name + ".jsonl")
            p.unlink()
            stream(p, rows)
        # Keep the independently scoped CBOM projection consistent with configured state, not network usage.
        change = {
            "bank_id": d["bank_id"],
            "hop_id": target["hop_id"],
            "previous": previous,
            "current": deepcopy(target),
            "affected_services": d["affected_services"],
            "timestamp": d["changed_at"],
            "evidence_type": "CONFIGURED",
            "previous_certificate": certs[previous["configured"]["certificate_id"]]["sha256"],
            "current_certificate": cert["sha256"],
            "negotiated_change": None,
            "actual_execution": False,
            "sha1_is_declaration_not_pem_signature": True,
            "clock_kind": "SIMULATED",
        }
        evidence = list(records(folder / "evidence.jsonl"))
        for e in evidence:
            if e["normalized_fact"]["hop_id"] == target["hop_id"]:
                e["timestamp"] = d["changed_at"]
                e["normalized_fact"]["configured"] = deepcopy(target["configured"])
                change["evidence_id"] = e["evidence_id"]
        p = folder / "evidence.jsonl"
        p.unlink()
        stream(p, evidence)
        truthfile = root / "control/ground_truth" / (d["bank_id"] + "-loadbalancers.jsonl")
        truth = list(records(truthfile))
        for t in truth:
            for h in t["modeled_sessions"]:
                if h["hop_id"] == target["hop_id"]:
                    h["certificate_id"] = cert["certificate_id"]
                    h.update(
                        certificate_fingerprint_sha256=cert["sha256"],
                        certificate_public_key_algorithm=cert["public_key_algorithm"],
                        certificate_key_size=cert["key_size"],
                        certificate_curve=cert["curve"],
                        certificate_signature_algorithm=cert["signature_algorithm"],
                    )
        truthfile.unlink()
        stream(truthfile, truth)
        changes.append(change)
    dump(
        root / "control/expected_results/lb-drift.json",
        {"changes": changes, "synthetic": True, "actual_execution": False},
    )
    return changes

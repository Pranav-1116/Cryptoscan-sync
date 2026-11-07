"""Linked, public-only LB inputs and separately written hidden semantic expectations.

No sockets, source execution, deployment, private-key serialization or product output fabrication.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tools.banking_sandbox.common import dump, stream, identifier
from tools.banking_sandbox import documents, pki
from tools.banking_sandbox.load_balancers.catalog import ROLES, SCENARIOS, POLICIES, CONFIG_STATES, REENCRYPT


def public_certificate(public, bank, identity, seed, epoch, kind="ECDSA-P256", expired=False, domains=None):
    """Deterministic public PEM; synthetic issuer seed is public test data, never production PKI."""
    dt = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
    sans = domains or [identity + ".lab.invalid", "payments." + identity + ".lab.invalid"]
    key = (
        pki.rsa_public(int(kind.split("-")[1]))
        if kind.startswith("RSA-")
        else ec.derive_private_key(
            1 + int.from_bytes(hashlib.sha256(identity.encode()).digest()[:16], "big"), ec.SECP256R1()
        ).public_key()
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SYNTHETIC LAB ONLY"),
            x509.NameAttribute(NameOID.COMMON_NAME, bank + " SYNTHETIC ISSUING"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .issuer_name(issuer)
        .public_key(key)
        .serial_number(int.from_bytes(hashlib.sha256((seed + identity).encode()).digest()[:19], "big") or 1)
        .not_valid_before(dt - timedelta(days=365))
        .not_valid_after(dt + timedelta(days=-1 if expired else 90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in sans]), False)
        .sign(pki.lab_key(seed, bank + "-ISSUING"), None)
    )
    ref = f"load_balancers/{bank}/certificates/{identity}.pem"
    path = public / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return {
        "certificate_id": identity + "-cert",
        "pem_ref": ref,
        "chain_refs": [f"pki/{bank}-{level}.pem" for level in ("issuing", "intermediate", "root")],
        "public_key_algorithm": "RSA" if kind.startswith("RSA") else "EC",
        "key_size": key.key_size,
        "curve": None if kind.startswith("RSA") else "secp256r1",
        "signature_algorithm": "Ed25519",
        "san": sans,
        "issuer": issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "private_key_reference": "LB-KEY-" + identity,
        "private_key_exported": False,
        "rotation": {
            "previous_certificate_id": None,
            "next_rotation": (dt + timedelta(days=60)).isoformat(),
            "status": "EXPIRED" if expired else "CURRENT",
            "clock_kind": "SIMULATED",
        },
        "synthetic": True,
    }


def generate_bank(public, control, bank, metadata, apps, systems, seed, epoch, legacy=True, conflicts=True, drift=True):
    folder = public / "load_balancers" / bank
    folder.mkdir(parents=True)
    archetype = metadata["archetype"]
    roles = list(ROLES[:9]) + ["data-center"]
    if archetype in ("cloud-first", "digital-only", "hybrid-cloud", "fintech-hybrid"):
        roles += ["kubernetes-ingress", "synthetic-cloud"]
    if archetype in ("payment-processor", "hsm-heavy", "card-issuer", "acquirer"):
        roles += ["payment-zone"]
    if archetype in ("multinational", "central-bank-like", "regulated"):
        roles += ["multi-site", "dr-site"]
    if archetype == "legacy-heavy":
        roles += ["dr-site"]
    nodes = []
    certs = []
    all_components = []
    boms = []
    cboms = []
    evidence = []
    hops = []
    cases = []
    truth = []
    edges = []
    clusters = []
    keys = []
    for i, role in enumerate(roles):
        node_id = f"{bank}-lb-{i:02d}"
        cert = public_certificate(public, bank, node_id, seed, epoch, "RSA-2048" if i % 2 else "ECDSA-P256")
        certs.append(cert)
        components = [
            {
                "component_id": node_id + "-component-" + str(j),
                "name": name,
                "declared_version": version,
                "bank_id": bank,
                "lb_id": node_id,
                "usage": "UNKNOWN_NOT_PROVEN_BY_SBOM",
            }
            for j, (name, version) in enumerate(
                [
                    ("SYNTHETIC-LB-software", "1.0-LAB"),
                    ("OpenSSL", "3.0.11"),
                    ("libcrypto", "3.0.11"),
                    ("libssl", "3.0.11"),
                ]
            )
        ]
        all_components += components
        node = {
            "lb_id": node_id,
            "bank_id": bank,
            "role": role,
            "system_id": systems[i % len(systems)]["system_id"],
            "data_center": metadata["data_centers"][i % 2],
            "software_based": True,
            "firmware": "1." + str(i % 3) + "-LAB",
            "backend_targets": [apps[i % len(apps)]["app_id"]],
            "certificate_ids": [cert["certificate_id"]],
            "key_reference": cert["private_key_reference"],
            "config_refs": [],
            "sbom_ref": f"sbom/{bank}-loadbalancers.jsonl",
            "component_ids": [c["component_id"] for c in components],
            "image_ref": None,
            "image_digest": None,
            "evidence_type": "CONFIGURED",
            "synthetic": True,
        }
        nodes.append(node)
        app = {"app_id": node_id, "name": node_id}
        boms.extend(
            [
                {"target": node_id, "document": documents.sbom(app, components, epoch), "synthetic": True},
                {
                    "target": node_id,
                    "format": "SPDX",
                    "document": documents.spdx(app, components, epoch),
                    "synthetic": True,
                },
            ]
        )
    (folder / "policies").mkdir()
    (folder / "policies" / "modern.conf").write_text(
        "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n"
    )
    dump(
        folder / "environment.json",
        {"synthetic": True, "LAB_TLS_VERSIONS": "TLSv1.2 TLSv1.3", "LAB_TLS_CIPHERS": "ECDHE-RSA-AES256-GCM-SHA384"},
    )
    # A real inert OCI layout, not a runnable image or evidence of use.
    from tools.banking_sandbox.generator import image_layout

    nodes[-1]["image_digest"] = image_layout(folder / "oci", bank, {"app_id": nodes[-1]["lb_id"]}, epoch)
    nodes[-1]["image_ref"] = f"load_balancers/{bank}/oci/index.json"
    nodes[-1]["containerized"] = True
    for mode, offset in [("active-standby", 0), ("active-active", 2), ("primary-dr", 4)]:
        members = nodes[offset : offset + 2]
        clusters.append(
            {
                "cluster_id": bank + "-lb-cluster-" + mode,
                "mode": mode,
                "members": [n["lb_id"] for n in members],
                "member_states": [
                    {
                        "lb_id": n["lb_id"],
                        "state": "ACTIVE" if j == 0 or mode == "active-active" else "STANDBY",
                        "certificate_id": n["certificate_ids"][0],
                        "configured_version": "TLS1.3" if j == 0 else "TLS1.2",
                        "firmware": n["firmware"],
                        "certificate_sync": "CURRENT" if j == 0 else "STALE",
                        "policy_id": "modern" if j == 0 else "mixed",
                    }
                    for j, n in enumerate(members)
                ],
                "synchronized_certificate_example": [members[0]["certificate_ids"][0]] * 2,
                "synthetic": True,
                "evidence_type": "CONFIGURED",
            }
        )
    for index, name in enumerate(SCENARIOS):
        node = nodes[index % len(nodes)]
        if name == "cloud-like":
            node = next((n for n in nodes if n["role"] == "synthetic-cloud"), nodes[-1])
        if name == "containerized":
            node = nodes[-1]
        case_id = f"{bank}-lb-case-{index + 1:02d}"
        lb = node["lb_id"]
        app = apps[index % len(apps)]
        cert = certs[nodes.index(node)]
        if name in ("expired-certificate", "stale-certificate", "multiple-sni-certificates", "hsm-key", "hsm-signing"):
            cert = public_certificate(
                public,
                bank,
                case_id,
                seed,
                epoch,
                "RSA-3072" if name in ("hsm-key", "hsm-signing") else "RSA-2048",
                name == "expired-certificate",
            )
            if name == "stale-certificate":
                cert["rotation"]["status"] = "STALE"
            certs.append(cert)
            node["certificate_ids"].append(cert["certificate_id"])
        passthrough = name in ("tls-passthrough", "passthrough-kubernetes")
        mode = (
            "PASSTHROUGH"
            if passthrough
            else "RE_ENCRYPTION"
            if name in REENCRYPT or name == "mtls-termination"
            else "TERMINATION"
        )
        policy = (
            "legacy"
            if name == "legacy-policy" and legacy
            else "mixed"
            if name in ("mixed-policy", "supported-not-negotiated")
            else "modern"
        )
        state = CONFIG_STATES[index % len(CONFIG_STATES)]
        path = case_id + "-path"
        backend = app["app_id"]
        listener = {
            "listener_id": case_id + "-listener",
            "lb_id": lb,
            "port": 443,
            "address": f"2001:db8:{int(bank.split('-')[1]):x}::{index + 1:x}",
            "sni": cert["san"],
            "alpn": ["h2", "http/1.1"],
            "mode": mode,
            "policy_id": policy,
            "configuration_state": state,
            "private_key_reference": None if passthrough else cert["private_key_reference"],
            "certificate_id": None if passthrough else cert["certificate_id"],
            "backend_certificate_id": cert["certificate_id"] if passthrough else None,
            "trusted_ca": f"pki/{bank}-root.pem",
            "backend_targets": [backend],
            "client_certificate_required": name in ("mtls-termination", "mtls-re-encryption"),
            "upstream_client_certificate_required": name in ("mtls-re-encryption", "service-mesh-mtls"),
            "redirect": {"from_port": 80, "to_port": 443, "status": 308} if name == "http-https-redirect" else None,
        }
        listener["sni_certificates"] = {domain: cert["certificate_id"] for domain in cert["san"]}
        if name == "multiple-sni-certificates":
            other = certs[nodes.index(node)]
            listener["sni_certificates"][other["san"][0]] = other["certificate_id"]
            listener["sni"] = list(listener["sni_certificates"])
        path_hops = []

        def hop(suffix, source, target, tls, certificate, version, cipher, mtls, visibility="VISIBLE"):
            h = {
                "hop_id": case_id + "-" + suffix,
                "path_id": path,
                "bank_id": bank,
                "lb_id": lb,
                "listener_id": listener["listener_id"],
                "source": source,
                "destination": target,
                "backend_target": backend,
                "port": 443 if tls else 8080,
                "transport": "TLS" if tls else "HTTP",
                "termination_point": target,
                "crypto_asset_id": case_id + "-" + suffix + "-crypto" if tls else None,
                "supported": deepcopy(POLICIES[policy if suffix in ("external", "end-to-end") else "modern"])
                if tls
                else None,
                "configured": {
                    "version": version,
                    "cipher_preference": cipher,
                    "key_exchange": None
                    if not tls
                    else "RSA"
                    if policy == "legacy" and suffix == "external"
                    else "X25519"
                    if version == "TLS1.3"
                    else "ECDHE",
                    "mtls_required": mtls,
                    "certificate_id": certificate["certificate_id"] if tls else None,
                    "sni": certificate["san"][0] if tls else None,
                    "alpn": ["h2", "http/1.1"] if tls else [],
                },
                "negotiated": None,
                "evidence_type": "CONFIGURED",
                "visibility": visibility,
                "timestamp": epoch,
                "clock_kind": "SIMULATED",
                "actual_execution": False,
                "synthetic": True,
            }
            path_hops.append(h)
            return h

        if passthrough:
            h = hop("end-to-end", "client", backend, True, cert, "TLS1.3", "AES-256-GCM", False)
            h["via"] = [lb]
            h["backend_kind"] = "KUBERNETES_INGRESS" if name == "passthrough-kubernetes" else "APPLICATION"
        else:
            hop(
                "external",
                "client",
                lb,
                True,
                cert,
                "TLS1.0" if policy == "legacy" else "TLS1.3",
                "AES-128-CBC" if policy == "legacy" else "AES-256-GCM",
                listener["client_certificate_required"],
            )
            if mode == "RE_ENCRYPTION":
                backend_cert = public_certificate(public, bank, case_id + "-backend", seed, epoch, "RSA-2048")
                certs.append(backend_cert)
                listener["backend_certificate_id"] = backend_cert["certificate_id"]
                hop(
                    "internal",
                    lb,
                    backend,
                    True,
                    backend_cert,
                    "TLS1.3" if name == "service-mesh-mtls" else "TLS1.2",
                    "AES-256-GCM" if name == "service-mesh-mtls" else "AES-128-GCM",
                    listener["upstream_client_certificate_required"],
                    "UNKNOWN" if name == "external-only-visibility" else "VISIBLE",
                )
            else:
                hop("internal", lb, backend, False, cert, None, None, False)
        if name == "api-gateway-service":
            path_hops[0]["source"] = bank + "-waf"
            path_hops[1]["destination"] = path_hops[1]["termination_point"] = bank + "-api-gateway"
            hop("internet-waf", "client", bank + "-waf", True, cert, "TLS1.3", "AES-256-GCM", False)
            hop(
                "gateway-mesh", bank + "-api-gateway", bank + "-service-mesh", True, cert, "TLS1.3", "AES-256-GCM", True
            )
            hop("mesh-service", bank + "-service-mesh", backend, True, cert, "TLS1.3", "AES-256-GCM", True)
            hop("service-database", backend, bank + "-database", True, backend_cert, "TLS1.2", "AES-128-GCM", False)
        if name == "different-backend-policies":
            extra = apps[(index + 1) % len(apps)]["app_id"]
            listener["backend_targets"].append(extra)
            hop("internal-secondary", lb, extra, True, cert, "TLS1.3", "AES-256-GCM", True)["backend_target"] = extra
        if name in ("hsm-key", "hsm-signing"):
            keyref = "HSM-KEY-" + case_id
            node.setdefault("hsm_integrations", []).append(
                {"hsm_id": bank + "-hsm-0", "key_reference": keyref, "certificate_id": cert["certificate_id"]}
            )
            cert["private_key_reference"] = keyref
            listener["private_key_reference"] = keyref
            keys.append(
                {
                    "key_reference": keyref,
                    "hsm_id": bank + "-hsm-0",
                    "certificate_id": cert["certificate_id"],
                    "bank_id": bank,
                    "lb_id": lb,
                    "algorithm": "RSA",
                    "key_size": 3072,
                    "lifecycle": "ACTIVE",
                    "signing_capability": "RSA-PSS",
                    "interface": "PKCS#11-SIMULATED",
                    "actual_execution": False,
                    "evidence_type": "VENDOR_DECLARED",
                    "synthetic": True,
                }
            )
        config = {
            "synthetic": True,
            "bank_id": bank,
            "case_id": case_id,
            **listener,
            "configured_policy": POLICIES[policy],
            "tls_minimum": POLICIES[policy]["versions"][0],
            "tls_maximum": POLICIES[policy]["versions"][-1],
            "upstream_tls": mode == "RE_ENCRYPTION",
            "resolution": {
                "state": state,
                "parent_policy": policy if state == "inherited" else None,
                "environment_reference": "LAB_TLS_POLICY" if state == "environment-driven" else None,
                "policy_reference": "policies.json#" + policy if state == "indirect" else None,
                "missing_fields": ["tls_minimum", "tls_maximum"] if state == "missing" else [],
                "conflicting_policy": "legacy" if state == "conflicting" and conflicts else None,
            },
            "evidence_type": "VENDOR_DECLARED" if state == "vendor-declared" else "CONFIGURED",
        }
        if state == "missing":
            config["tls_minimum"] = config["tls_maximum"] = None
        casefolder = folder / case_id
        casefolder.mkdir()
        dump(casefolder / "loadbalancer.json", config)
        # Templates are intentionally inert: certificate/key tokens are references, never deployable secrets.
        from tools.banking_sandbox.load_balancers.configurations import snippets as config_snippets

        snippets = config_snippets(config, cert)
        for filename, text in snippets.items():
            (casefolder / filename).write_text(text)
        # JSON is a YAML subset; both manifests are parseable without custom constructors.
        dump(casefolder / "envoy.yaml", {"synthetic": True, "tls_context": config})
        dump(
            casefolder / "gateway.yaml",
            {"synthetic": True, "kind": "Gateway", "apply_authorized": False, "listener": listener},
        )
        configref = f"load_balancers/{bank}/{case_id}/loadbalancer.json"
        node["config_refs"].append(configref)
        mode_conflict = (
            name in ("vendor-network-conflict", "sbom-runtime-conflict", "stale-cbom-network-conflict") and conflicts
        )
        modeled = [
            {
                "hop_id": h["hop_id"],
                "crypto_asset_id": h["crypto_asset_id"],
                "termination_point": h["termination_point"],
                "certificate_id": h["configured"]["certificate_id"],
                "path_id": path,
                "certificate_fingerprint_sha256": next(
                    c["sha256"] for c in certs if c["certificate_id"] == h["configured"]["certificate_id"]
                ),
                "certificate_public_key_algorithm": next(
                    c["public_key_algorithm"] for c in certs if c["certificate_id"] == h["configured"]["certificate_id"]
                ),
                "certificate_key_size": next(
                    c["key_size"] for c in certs if c["certificate_id"] == h["configured"]["certificate_id"]
                ),
                "certificate_curve": next(
                    c["curve"] for c in certs if c["certificate_id"] == h["configured"]["certificate_id"]
                ),
                "certificate_signature_algorithm": next(
                    c["signature_algorithm"] for c in certs if c["certificate_id"] == h["configured"]["certificate_id"]
                ),
                "version": h["configured"]["version"],
                "cipher": h["configured"]["cipher_preference"],
                "mtls_required": h["configured"]["mtls_required"],
                "expected_evidence_type": "NETWORK_OBSERVED",
                "backend_target": h["backend_target"],
            }
            for h in path_hops
            if h["transport"] == "TLS"
        ]
        truth.append(
            {
                "case_id": case_id,
                "bank_id": bank,
                "scenario": name,
                "lb_id": lb,
                "listener_id": listener["listener_id"],
                "mode": mode,
                "termination_points": [h["termination_point"] for h in modeled],
                "modeled_sessions": modeled,
                "actual_negotiated_crypto": None,
                "runtime_crypto": None,
                "actual_results_required": True,
                "model_is_not_live_evidence": True,
                "expected_conflict": mode_conflict,
                "hsm_key_reference": listener["private_key_reference"] if name in ("hsm-key", "hsm-signing") else None,
                "sbom_components": node["component_ids"],
                "expected_correlation": "SEPARATE_HOPS_NOT_APPLICATION_CRYPTO",
            }
        )
        cases.append(
            {
                "case_id": case_id,
                "bank_id": bank,
                "scenario": name,
                "lb_id": lb,
                "listener": listener,
                "path_id": path,
                "hop_ids": [h["hop_id"] for h in path_hops],
                "config_ref": configref,
                "cluster_ref": clusters[2]["cluster_id"]
                if name == "primary-dr-difference"
                else clusters[0]["cluster_id"]
                if name in ("ha-pair", "ha-certificate-drift")
                else None,
                "fixture_only": True,
                "claim_sources": {
                    "vendor": {
                        "cipher": "3DES" if mode_conflict else "AES-256-GCM",
                        "evidence_type": "VENDOR_DECLARED",
                    },
                    "runtime": {
                        "provider": "SYNTHETIC-provider" if name == "sbom-runtime-conflict" else None,
                        "evidence_type": "IMPORTED",
                        "actual_execution": False,
                    },
                    "stale_cbom": {
                        "algorithm": "AES-128-CBC" if name == "stale-cbom-network-conflict" else None,
                        "evidence_type": "IMPORTED",
                    },
                },
                "application_crypto": {"algorithm": "HMAC-SHA256", "evidence_type": "CONFIGURED"}
                if name == "certificate-not-application-crypto"
                else None,
                "additional_domains": cert["san"],
                "synthetic": True,
            }
        )
        for h in path_hops:
            hops.append(h)
            ev = {
                "evidence_id": identifier(bank, h["hop_id"], "lb-config"),
                "source": configref,
                "collector": "SYNTHETIC-LB-fixture-producer",
                "timestamp": epoch,
                "clock_kind": "SIMULATED",
                "bank_id": bank,
                "target": lb,
                "system": node["system_id"],
                "application": h["backend_target"],
                "process": None,
                "network_endpoint": listener["listener_id"],
                "component": lb,
                "evidence_type": "CONFIGURED",
                "raw_observation_reference": configref,
                "normalized_fact": {"hop_id": h["hop_id"], "transport": h["transport"], "configured": h["configured"]},
                "confidence": "DECLARED",
                "provenance": "SYNTHETIC/LAB",
                "actual_execution": False,
            }
            evidence.append(ev)
            h["evidence_ids"] = [ev["evidence_id"]]
            if h["crypto_asset_id"]:
                cboms.append(
                    {
                        "target": h["crypto_asset_id"],
                        "hop_id": h["hop_id"],
                        "bank_id": bank,
                        "synthetic": True,
                        "document": documents.cbom(
                            {"app_id": h["crypto_asset_id"]}, h["configured"]["cipher_preference"], "NETWORK_TRANSPORT"
                        ),
                    }
                )
        for h in path_hops:
            route = [h["source"], *h.get("via", []), h["destination"]]
            for a, b in zip(route, route[1:]):
                edges.append(
                    {
                        "bank_id": bank,
                        "path_id": path,
                        "from": a,
                        "to": b,
                        "relationship": "FORWARDS_UNCHANGED_TLS" if passthrough else "CONFIGURED_PATH",
                        "session_hop_ids": [h["hop_id"]],
                        "evidence_type": "CONFIGURED",
                        "synthetic": True,
                    }
                )
    drift_cert = public_certificate(
        public, bank, bank + "-lb-rotation", seed, epoch, "RSA-2048", domains=certs[0]["san"]
    )
    drift_cert["rotation"]["status"] = "NEXT"
    certs.append(drift_cert)
    nodes[0]["certificate_ids"].append(drift_cert["certificate_id"])
    dump(
        folder / "inventory.json",
        {
            "version": "SYNTHETIC_LB_V1",
            "bank_id": bank,
            "nodes": nodes,
            "clusters": clusters,
            "support_nodes": [
                {"asset_id": bank + "-" + k, "kind": k} for k in ("waf", "api-gateway", "service-mesh", "database")
            ],
            "synthetic": True,
        },
    )
    dump(
        folder / "policies.json",
        {"bank_id": bank, "policies": POLICIES, "evidence_type": "CONFIGURED", "synthetic": True},
    )
    for name, rows in [
        ("cases", cases),
        ("hops", hops),
        ("certificates", certs),
        ("evidence", evidence),
        ("keys", keys),
    ]:
        stream(folder / (name + ".jsonl"), rows)
    for projection, rows in [
        ("sbom", boms),
        ("cbom", cboms),
        ("nbom", edges),
        ("techbom", all_components),
        ("hbom", nodes),
        (
            "vbom",
            [
                {
                    "bank_id": bank,
                    "lb_id": n["lb_id"],
                    "vendor": "SYNTHETIC-ADC-" + archetype,
                    "evidence_type": "VENDOR_DECLARED",
                    "synthetic": True,
                }
                for n in nodes
            ],
        ),
    ]:
        stream(public / projection / (bank + "-loadbalancers.jsonl"), rows)
    stream(public / "hsm" / (bank + "-loadbalancers.jsonl"), keys)
    runtime_claims = []
    stale_cboms = []
    for case in cases:
        if case["scenario"] == "sbom-runtime-conflict":
            node = next(n for n in nodes if n["lb_id"] == case["lb_id"])
            runtime_claims.append(
                {
                    "bank_id": bank,
                    "lb_id": node["lb_id"],
                    "case_id": case["case_id"],
                    "component_id": node["component_ids"][2],
                    "declared_loaded_provider": "LibreSSL-like-LAB",
                    "declared_loaded_version": "3.0.0",
                    "sbom_version": "3.0.11",
                    "evidence_type": "IMPORTED",
                    "actual_execution": False,
                    "synthetic": True,
                }
            )
        if case["scenario"] == "stale-cbom-network-conflict":
            h = next(h for h in hops if h["hop_id"] == case["hop_ids"][0])
            stale_cboms.append(
                {
                    "target": h["crypto_asset_id"],
                    "hop_id": h["hop_id"],
                    "evidence_type": "IMPORTED",
                    "timestamp": (
                        datetime.fromisoformat(epoch.replace("Z", "+00:00")) - timedelta(days=30)
                    ).isoformat(),
                    "synthetic": True,
                    "document": documents.cbom({"app_id": h["crypto_asset_id"]}, "AES-128-CBC", "NETWORK_TRANSPORT"),
                }
            )
    stream(public / "runtime" / (bank + "-loadbalancers.jsonl"), runtime_claims)
    stream(public / "cbom" / (bank + "-loadbalancers-stale.jsonl"), stale_cboms)
    stream(control / "ground_truth" / (bank + "-loadbalancers.jsonl"), truth)
    dump(
        folder / "drift.json",
        {
            "bank_id": bank,
            "enabled": drift,
            "baseline_time": epoch,
            "changed_at": (datetime.fromisoformat(epoch.replace("Z", "+00:00")) + timedelta(days=1)).isoformat(),
            "target_hop": cases[0]["hop_ids"][0],
            "affected_services": nodes[0]["backend_targets"],
            "new_capability": {"versions": ["TLS1.2", "TLS1.3"], "ciphers": ["AES-256-GCM", "AES-128-CBC"]},
            "certificate_transition": {
                "from": certs[0]["certificate_id"],
                "to": drift_cert["certificate_id"],
            },
            "sha1_signature_declaration": "SHA-1",
            "actual_sha1_certificate_generated": False,
            "negotiated_change": None,
            "clock_kind": "SIMULATED",
            "actual_execution": False,
            "synthetic": True,
        },
    )
    return {
        "load_balancers": len(nodes),
        "lb_scenarios": len(cases),
        "lb_crypto_hops": len(cboms),
        "lb_certificates": len(certs),
        "lb_sbom_documents": len(boms),
    }

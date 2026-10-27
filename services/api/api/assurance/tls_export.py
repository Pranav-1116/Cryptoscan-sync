"""NBOM/CBOM session projection from retained originals, never a network probe."""

import json
import uuid
from shared_models.host_collection import digest
from shared_models.tls_session import endpoint


def props(value):
    return [
        {
            "name": "cryptoscan:" + k,
            "value": v if isinstance(v, str) else json.dumps(v, sort_keys=True, separators=(",", ":")),
        }
        for k, v in sorted(value.items())
    ]


def session_bom(snapshot, records, approval_id):
    requested = {
        i.input_id
        for i in snapshot.manifest.inputs
        if i.kind in {"NETWORK_TLS_SESSION", "NETWORK_TLS13_KEY_SHARE", "NETWORK_TLS13_HYBRID"}
    }
    certs, components, services, failures = {}, [], {}, []
    for receipt in snapshot.receipts:
        if receipt.input_id not in requested:
            continue
        if receipt.status != "PARSED":
            failures.append({"input_id": receipt.input_id, "status": receipt.status, "reason": receipt.reason})
            continue
        f = receipt.facts[0]
        proofs = sorted(
            r.id for r in records if r.finding_data.get("host_evidence", {}).get("input_id") == receipt.input_id
        )
        if not proofs:
            raise ValueError("Retained receipt evidence required")
        source = {
            "input_id": receipt.input_id,
            "evidence_ids": proofs,
            "selected_sha256": receipt.content_sha256,
            "snapshot_sha256": digest(snapshot),
            "reviewed_target_sha256": f.reviewed_target_sha256,
            "authorized_operation": f.authorized_operation,
            "source_basis": "IMPORTED",
            "local_basis": "OBSERVED",
        }
        cert = f.certificate.model_dump(mode="json")
        pin = f.certificate.fingerprint_sha256
        if pin in certs and certs[pin]["cert"] != cert:
            raise ValueError("Conflicting same-certificate metadata")
        group = certs.setdefault(pin, {"cert": cert, "sources": []})
        group["sources"].append(source)
        ref = "tls-session-observation:" + digest({"input_id": receipt.input_id, "fact": f.model_dump(mode="json")})
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f"Observed {f.tls_version} session cipher {f.cipher_suite}",
                "cryptoProperties": {"assetType": "protocol"},
                "properties": props(
                    {
                        "endpoint_ref": f.identity_key,
                        "certificate_ref": "certificate:sha256:" + pin,
                        "tls_version": f.tls_version,
                        "cipher_suite": f.cipher_suite,
                        "cipher_bits": f.cipher_bits,
                        "sni": f.sni,
                        "source": source,
                        "key_exchange_group": f.key_exchange_group,
                        **(
                            {
                                "selected_group_id": f.selected_group_id,
                                "group_classification": f.group_classification,
                                "group_classification_basis": f.group_classification_basis,
                                "server_hello_sha256": f.server_hello_sha256,
                                "server_hello_hex": f.server_hello_hex,
                                "hello_retry_request_seen": f.hello_retry_request_seen,
                                "pqc_implementation_verified": False,
                                "pqc_readiness_verified": False,
                                "all_groups_tested": False,
                            }
                            if f.kind in {"NETWORK_TLS13_KEY_SHARE", "NETWORK_TLS13_HYBRID"}
                            else {}
                        ),
                        **(
                            {
                                "hybrid_session_completed": True,
                                "tls_provider": f.tls_provider,
                                "openssl_version": f.openssl_version,
                                "pyopenssl_version": f.pyopenssl_version,
                                "cryptography_version": f.cryptography_version,
                                "provider_identity_basis": f.provider_identity_basis,
                            }
                            if f.kind == "NETWORK_TLS13_HYBRID"
                            else {}
                        ),
                        "server_signature_scheme": "UNKNOWN",
                        "certificate_chain_validated": False,
                        "hostname_validated": False,
                        "revocation_checked": False,
                        "all_tls_versions_tested": False,
                        "application_identity_verified": False,
                        "runtime_use": "UNKNOWN",
                        "policy_result": "NOT_EVALUATED",
                        "pqc_assessment": "UNKNOWN",
                    }
                ),
            }
        )
        service = services.setdefault(f.identity_key, {"fact": f, "sessions": []})
        service["sessions"].append({"observation_ref": ref, "certificate_ref": "certificate:sha256:" + pin, **source})
    if not components:
        raise ValueError("No parsed approved TLS session; failed probes are not absence")
    for pin, group in sorted(certs.items()):
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": "certificate:sha256:" + pin,
                "name": "Observed peer certificate SHA-256 " + pin,
                "cryptoProperties": {"assetType": "certificate"},
                "properties": props(
                    {
                        **group["cert"],
                        "public_key_metadata_only": True,
                        "sources": sorted(group["sources"], key=lambda s: s["input_id"]),
                        "certificate_chain_validated": False,
                        "hostname_validated": False,
                        "signature_use_in_session": "UNKNOWN",
                    }
                ),
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, "cryptoscan:tls-session:" + approval_id + ":" + digest(snapshot))),
        "metadata": {
            "properties": props(
                {
                    "profile": "PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN",
                    "approval_id": approval_id,
                    "snapshot_sha256": digest(snapshot),
                    "source_basis": "IMPORTED",
                    "projection_domains": ["NBOM", "CBOM", "TechBOM"],
                    "failed_inputs": failures,
                    "complete_inventory_verified": False,
                    "production_execution_qualified": False,
                }
            )
        },
        "components": sorted(components, key=lambda c: c["bom-ref"]),
        "services": [
            {
                "bom-ref": identity,
                "name": entry["fact"].sni,
                "endpoints": ["tls://" + endpoint(entry["fact"].address, entry["fact"].port)],
                "properties": props(
                    {
                        "identity_basis": "APPROVED_NUMERIC_ENDPOINT_AND_SNI_NOT_APPLICATION",
                        "observed_sessions": entry["sessions"],
                        "application_identity_verified": False,
                    }
                ),
            }
            for identity, entry in sorted(services.items())
        ],
        "compositions": [{"aggregate": "incomplete"}],
    }

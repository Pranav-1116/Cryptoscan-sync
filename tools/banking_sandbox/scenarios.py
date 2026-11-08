"""Relational test cases. Claims keep distinct subjects, layers and epistemic states."""

from tools.banking_sandbox.catalog import DIFFICULT, FAILURES
from tools.banking_sandbox.common import identifier


def scenarios(bank, apps, systems, epoch, drift=True):
    rows = []
    truth = []
    for i, name in enumerate(DIFFICULT):
        app = apps[i % len(apps)]
        other = apps[(i + 1) % len(apps)]
        subject = app["app_id"]
        layer = "application"
        a = "AES-256"
        b = None
        state = "CONFIGURED"
        key_size = 256
        details = {"synthetic": True, "actual_execution": False}
        if name == "shared-library-20-apps":
            details.update(applications=[x["app_id"] for x in apps[:20]], component=bank + "-shared-lib")
        elif name == "application-multiple-versions":
            a = "OpenSSL-3.0.13"
            b = "OpenSSL-3.0.11"
            layer = "component-version"
            details.update(deployments=[subject, other["app_id"]])
        elif name == "shared-ip-multiple-services":
            details.update(ip=app["ip"], services=app["service_ids"], identity_key=["bank_id", "ip", "port", "sni"])
        elif name == "lb-tls-termination":
            a = "TLS1.3"
            b = "TLS1.2"
            layer = "transport"
            details.update(terminates_at="external-lb", backend=subject)
        elif name == "internal-reencryption":
            a = "TLS1.2"
            layer = "internal-transport"
            details.update(algorithm="AES-128-GCM")
        elif name == "mesh-mtls":
            a = "TLS1.3"
            layer = "sidecar-transport"
            details.update(mtls=True, actor=subject + "-sidecar")
        elif name == "application-encryption-over-tls":
            details.update(transport="TLS1.3", application_encryption="AES-256-GCM")
        elif name in ("hsm-backed-rsa", "hsm-signing-source-invisible"):
            a = "RSA-PSS"
            key_size = 2048
            layer = "hsm"
            details.update(key_ref=bank + "-hsm-key-0", operation="sign", source_visibility=False)
        elif name in ("kms-backed-aes", "kms-api-encryption"):
            layer = "kms"
            details.update(key_ref=apps[0]["app_id"] + "-kms-key", operation="encrypt", api_only=True)
        elif name == "certificate-vs-application-algorithm":
            a = "RSA-2048"
            b = "AES-256"
            layer = "certificate-vs-application"
            key_size = 2048
        elif name == "sbom-vs-runtime-provider":
            a = "OpenSSL"
            b = "SYNTHETIC-LibreSSL-like"
            layer = "provider"
            state = "IMPORTED"
        elif name == "installed-unused-library":
            a = "OpenSSL"
            state = "IMPORTED"
            details.update(installed=True, executed=False)
        elif name == "configured-not-negotiated":
            a = "TLS1.2"
            b = "TLS1.3"
            layer = "transport"
            details.update(configured=a, simulated_negotiated=b)
        elif name in ("weak-supported-not-negotiated", "strong-negotiated-weak-enabled"):
            a = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            b = "TLS_AES_256_GCM_SHA384"
            layer = "transport"
            details.update(supported=[a, b], simulated_negotiated=b)
        elif name == "vendor-only-no-independent-proof":
            state = "VENDOR_DECLARED"
            details.update(independently_verified=False, declared_fips_mode=True)
        elif name == "runtime-missing-sbom":
            state = "IMPORTED"
            details.update(simulated_evidence_type="RUNTIME_OBSERVED", sbom_present=False)
        elif name == "network-without-source":
            a = "TLS1.3"
            layer = "transport"
            details.update(source_present=False, simulated_evidence_type="NETWORK_OBSERVED")
        elif name == "source-without-runtime":
            state = "STATIC_OBSERVED"
            details.update(runtime_present=False, executed=False)
        elif name == "multiple-endpoint-certificates":
            details.update(certificates=app["certificate_ids"], selection="SNI")
        elif name == "expired-unused-certificate":
            layer = "certificate"
            details.update(expired=True, in_use=False)
        elif name == "rotation-stale-inventory":
            layer = "certificate"
            a = "previous-certificate"
            b = "rotated-certificate"
            details.update(inventory_stale=True)
        elif name == "primary-dr-difference":
            a = "TLS1.3"
            b = "TLS1.2"
            layer = "transport"
            details.update(environments=["production", "dr"])
        elif name == "dev-production-difference":
            a = "RSA-1024"
            b = "RSA-3072"
            key_size = 1024
            details.update(environments=["dev", "production"])
        elif name == "controlled-crypto-drift":
            a = "TLS1.3"
            b = "TLS1.2"
            layer = "transport"
            details.update(
                clock_kind="SIMULATED",
                baseline_time=epoch,
                offset_seconds=86400,
                enabled=drift,
                previous={"protocol": "TLS1.3", "cipher": "AES-256-GCM", "certificate": "ECDSA-P256"},
                new={"protocol": "TLS1.2", "cipher": "AES-128-GCM", "certificate": "RSA-2048"},
            )
        elif name == "unknown-implementation":
            a = None
            key_size = None
            state = "UNKNOWN"
            details.update(implementation="opaque", safe=False)
        elif name == "custom-wrapper":
            details.update(wrapper="ShieldEnvelope.encrypt", underlying="AES-256-GCM")
        elif name == "dynamic-native-library":
            details.update(loader="dlopen", library="SYNTHETIC-libshield.so", visibility="partial")
        elif name == "image-sbom-mismatch":
            a = "OpenSSL-3.0.13"
            b = "OpenSSL-3.0.11"
            layer = "component-version"
            details.update(image=app["image_digest"], sbom_stale=True)
        elif name == "sidecar-tls-not-application":
            a = "TLS1.3"
            layer = "sidecar-transport"
            details.update(actor=subject + "-sidecar", application_terminates_tls=False)
        elif name == "legacy-network-only":
            a = "TLS1.0"
            layer = "transport"
            details.update(source_present=False, sbom_present=False, network_metadata_only=True)
        elif name == "appliance-config-only":
            state = "CONFIGURED"
            details.update(source_present=False, sbom_present=False, config_export_only=True)
        elif name == "partial-passive-sensor":
            a = None
            key_size = None
            state = "UNKNOWN"
            details.update(coverage_fraction=0.25, unseen_traffic="UNKNOWN")
        evidence_id = identifier(bank, name, "evidence")
        row = {
            "case_id": identifier(bank, name),
            "bank_id": bank,
            "scenario": name,
            "subject": subject,
            "other_subject": other["app_id"],
            "layer": layer,
            "evidence_id": evidence_id,
            "evidence_type": state,
            "declaration": a,
            "conflicting_declaration": b,
            "comparison_scope": "SAME_SCOPE_CONFLICT"
            if name
            in (
                "application-multiple-versions",
                "sbom-vs-runtime-provider",
                "rotation-stale-inventory",
                "image-sbom-mismatch",
            )
            else "DISTINCT_LAYER_OR_STATE",
            "key_size": key_size,
            "details": details,
            "label": "SYNTHETIC LAB",
            "timestamp": epoch,
            "clock_kind": "SIMULATED",
        }
        rows.append(row)
        truth.append(
            {
                "bank_id": bank,
                "case_id": row["case_id"],
                "subject": subject,
                "layer": layer,
                "expected_evidence_type": state,
                "expected_algorithm": a,
                "expected_key_size": key_size,
                "expected_conflict": b is not None
                and name
                in (
                    "application-multiple-versions",
                    "sbom-vs-runtime-provider",
                    "rotation-stale-inventory",
                    "image-sbom-mismatch",
                ),
                "same_semantic_scope_conflict": name
                in (
                    "application-multiple-versions",
                    "sbom-vs-runtime-provider",
                    "rotation-stale-inventory",
                    "image-sbom-mismatch",
                ),
                "expected_runtime_usage": False
                if name in ("installed-unused-library", "source-without-runtime")
                else None,
                "expected_status": "UNKNOWN" if a is None else "DECLARED_OR_FIXTURE_NOT_LIVE",
                "expected_pqc": "UNKNOWN" if a is None else "REVIEW_REQUIRED",
                "owner": app["owner"],
                "system_id": app["system_id"],
                "endpoint_ids": app["service_ids"],
                "dependencies": app["component_ids"],
                "evidence_id": evidence_id,
                "synthetic": True,
            }
        )
    for name in FAILURES:
        rows.append(
            {
                "case_id": identifier(bank, name),
                "bank_id": bank,
                "scenario": name,
                "label": "SYNTHETIC LAB",
                "fault_kind": "DECLARED_FAILURE_FIXTURE",
                "actual_injection_executed": False,
                "timestamp": epoch,
                "clock_kind": "SIMULATED",
            }
        )
    return rows, truth

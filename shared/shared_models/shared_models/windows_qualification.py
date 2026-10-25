"""Pre-acquisition Windows packet checks, not dispatch, approval or native truth."""

from typing import Literal, get_args, get_origin
from pydantic import Field
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, Token, HostFact
from shared_models.host_runtime import RuntimeFact
from shared_models.windows_images import WindowsImageFact
from shared_models.windows_cng import WindowsCngFact, registration_resource, unsupported_expected_value
from shared_models.windows_tpm import WindowsTpmFact
from shared_models.windows_capi import WindowsCapiFact, provider_resource, PROVIDER_TYPES
from shared_models.windows_listeners import WindowsListenerFact, listener_resource
from shared_models.tpm_quote_verification import sha


class WindowsQualificationPreflight(Strict):
    schema_version: Literal["cryptoscan.windows-qualification-preflight/v1"] = (
        "cryptoscan.windows-qualification-preflight/v1"
    )
    status: Literal["PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR"] = "PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR"
    target_sha256: Digest
    plan_sha256: Digest
    source_lock_sha256: Digest
    input_ids: list[Token] = Field(min_length=2, max_length=100)
    native_execution_performed: Literal[False] = False
    independent_approval_verified: Literal[False] = False
    production_execution_qualified: Literal[False] = False
    container_admission_granted: Literal[False] = False


def prepare_windows_preflight(target, plan, source_sha, approved_plan_sha, approved_source_sha):
    if (
        not target.manifest
        or target.collection_method != "offline_host"
        or target.manifest.platform != "windows"
        or sha(target) != plan.target_sha256
        or sha(plan) != approved_plan_sha
        or source_sha != approved_source_sha
    ):
        raise ValueError("Explicit reviewed target/plan/source commitments required")
    inputs = {i.input_id: i for i in target.manifest.inputs}
    expected = {e.input_id: e for e in plan.expected}
    if len(expected) != len(plan.expected) or inputs.keys() != expected.keys():
        raise ValueError("Exact reviewed input/expected-truth scope required")
    if not {"WINDOWS_OS_RELEASE", "WINDOWS_SERVICE"} <= {i.kind for i in inputs.values()}:
        raise ValueError("Windows packet must retain existing OS and SCM native gates")
    if any(
        i.kind.startswith("LINUX_") or i.kind in {"DPKG_STATUS", "APK_INSTALLED", "RPM_SQLITE"} for i in inputs.values()
    ):
        raise ValueError("Linux interfaces cannot qualify Windows")
    fields = set().union(
        *(
            set(cls.model_fields)
            for cls in (
                HostFact,
                RuntimeFact,
                WindowsImageFact,
                WindowsCngFact,
                WindowsTpmFact,
                WindowsCapiFact,
                WindowsListenerFact,
            )
        )
    )
    for identifier, item in inputs.items():
        patterns = expected[identifier].facts
        for pattern in patterns:
            if (
                not pattern
                or "kind" not in pattern
                or set(pattern) - fields
                or any(unsupported_expected_value(k, v) for k, v in pattern.items())
            ):
                raise ValueError("Invalid independent expected-truth assertion")
        if item.kind in {
            "WINDOWS_CAPI_DEFAULT_PROVIDER",
            "WINDOWS_TCP_LISTENERS",
            "WINDOWS_CNG_REGISTRATION",
            "WINDOWS_TPM_DEVICE_INFO",
        }:
            if len(patterns) != 1:
                raise ValueError("One independently reviewed metadata fact required")
            p = patterns[0]
            model = {
                "WINDOWS_CAPI_DEFAULT_PROVIDER": WindowsCapiFact,
                "WINDOWS_TCP_LISTENERS": WindowsListenerFact,
                "WINDOWS_CNG_REGISTRATION": WindowsCngFact,
                "WINDOWS_TPM_DEVICE_INFO": WindowsTpmFact,
            }[item.kind]
            if set(p) - set(model.model_fields):
                raise ValueError("Assertion field belongs to another fact contract")
            for key, value in p.items():
                annotation = model.model_fields[key].annotation
                if (
                    get_origin(annotation) is Literal
                    and not any(type(value) is type(v) and value == v for v in get_args(annotation))
                    or annotation is type(None)
                    and value is not None
                ):
                    raise ValueError("Promoted or ill-typed metadata assertion")
            if (
                p.get("algorithm") != "UNKNOWN"
                or p.get("runtime_use") != "UNKNOWN"
                or p.get("capabilities_observed") is not False
            ):
                raise ValueError("Explicit unknown-use/false-capability expectations required")
            if item.kind == "WINDOWS_CAPI_DEFAULT_PROVIDER":
                if (
                    p.get("kind") != item.kind
                    or p.get("provider_type") != PROVIDER_TYPES[provider_resource(item.path)]
                    or p.get("provider_context") != "CURRENT_USER"
                    or not isinstance(p.get("provider_name"), str)
                ):
                    raise ValueError("Exact reviewed CAPI selection/name required")
            elif item.kind == "WINDOWS_CNG_REGISTRATION":
                if (
                    p.get("kind") != item.kind
                    or p.get("registration_interface") != registration_resource(item.path)
                    or not isinstance(p.get("registered_functions"), list)
                ):
                    raise ValueError("Exact reviewed registration labels/interface required")
            elif item.kind == "WINDOWS_TCP_LISTENERS":
                rows = p.get("listeners")
                if isinstance(rows, list):
                    import ipaddress

                    version = 4 if listener_resource(item.path) == "ipv4" else 6
                    if any(ipaddress.ip_address(row["address"]).version != version for row in rows):
                        raise ValueError("Reviewed TCP row outside approved address family")
                if (
                    p.get("kind") != "WINDOWS_TCP_LISTENER_TABLE"
                    or p.get("address_family") != listener_resource(item.path)
                    or not isinstance(rows, list)
                    or type(p.get("listener_count")) is not int
                    or p["listener_count"] != len(rows)
                    or p.get("tls_observed") is not False
                    or p.get("process_identity_verified") is not False
                ):
                    raise ValueError("Exact reviewed TCP rows/count and no TLS/process-identity claim required")
            elif (
                p.get("kind") != "WINDOWS_TPM_METADATA"
                or type(p.get("api_structure_version")) is not int
                or p["api_structure_version"] != 1
                or p.get("tpm_specification") not in {"1.2", "2.0"}
            ):
                raise ValueError("Independently reviewed TPM layout/specification required")
    return WindowsQualificationPreflight(
        target_sha256=sha(target), plan_sha256=sha(plan), source_lock_sha256=source_sha, input_ids=sorted(inputs)
    )

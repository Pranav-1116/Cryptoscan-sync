"""Canonical interface resources and fact-to-approved-resource consistency."""

import re


def certificate_resource(path):
    match = re.fullmatch(
        r"windows-cert://(current-user|local-machine)/(MY|ROOT|CA)/sha1/([0-9a-f]{40})/sha256/([0-9a-f]{64})", path
    )
    if not match:
        raise ValueError("Noncanonical or unsupported local certificate resource")
    return match.groups()


def resource(kind, path):
    if kind == "NETWORK_TLS13_HYBRID":
        from shared_models.tls_hybrid import hybrid_resource

        return hybrid_resource(path)
    if kind == "NETWORK_TLS13_KEY_SHARE":
        from shared_models.tls_key_share import key_share_resource

        return key_share_resource(path)
    if kind == "NETWORK_TLS_CLIENT_OFFER":
        from shared_models.tls_client_offer import client_offer_resource

        return client_offer_resource(path)
    if kind == "NETWORK_TLS_SESSION":
        from shared_models.tls_session import tls_resource

        return tls_resource(path)
    if kind in {"OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"}:
        from shared_models.oci_content import content_resource, runtime_resource

        return (content_resource if kind == "OCI_IMAGE_CONTENT" else runtime_resource)(path)
    if kind == "OCI_IMAGE_METADATA":
        from shared_models.oci_image import image_resource

        return image_resource(path)
    if kind == "WINDOWS_CAPI_DEFAULT_PROVIDER":
        from shared_models.windows_capi import provider_resource

        return provider_resource(path)
    if kind == "WINDOWS_TCP_LISTENERS":
        from shared_models.windows_listeners import listener_resource

        return listener_resource(path)
    if kind == "WINDOWS_TPM_DEVICE_INFO":
        from shared_models.windows_tpm import device_resource

        return device_resource(path)
    if kind == "WINDOWS_CNG_REGISTRATION":
        from shared_models.windows_cng import registration_resource

        return registration_resource(path)
    if kind == "WINDOWS_PROCESS_MODULES":
        from shared_models.windows_images import process_resource

        return process_resource(path)
    if kind == "WINDOWS_CERTIFICATE":
        return certificate_resource(path)
    patterns = {
        "LINUX_PROCESS": r"linux-proc://(self|[1-9][0-9]{0,8})/process",
        "LINUX_PROCESS_MAPS": r"linux-proc://(self|[1-9][0-9]{0,8})/maps",
        "LINUX_LISTENERS": r"linux-sockets://self/(tcp|tcp6)",
        "LINUX_SERVICE": r"systemd://([A-Za-z0-9_][A-Za-z0-9_.@:-]{0,110}\.service)",
        "LINUX_HARDWARE": r"linux-hardware://(dmi|tpm[0-9]{1,3}|cpu(?:0|[1-9][0-9]{0,3}))",
        "WINDOWS_SERVICE": r"windows-service://([A-Za-z0-9_][A-Za-z0-9_.-]{0,110})",
    }
    if kind not in patterns:
        return None
    match = re.fullmatch(patterns[kind], path)
    if not match:
        raise ValueError("Noncanonical or unsupported runtime resource")
    return match[1]


def validate_runtime_facts(item, facts):
    if item.kind in {"NETWORK_TLS13_KEY_SHARE", "NETWORK_TLS13_HYBRID"}:
        from shared_models.tls_key_share import key_share_resource
        from shared_models.tls_hybrid import hybrid_resource

        approved_resource = hybrid_resource if item.kind == "NETWORK_TLS13_HYBRID" else key_share_resource

        if facts and (
            len(facts) != 1
            or (
                facts[0].address,
                facts[0].port,
                facts[0].sni,
                facts[0].tls_version,
                facts[0].certificate.fingerprint_sha256,
            )
            != approved_resource(item.path)
        ):
            raise ValueError("Key-share fact outside exact approved scope")
        return

    if item.kind == "NETWORK_TLS_CLIENT_OFFER":
        from shared_models.tls_client_offer import validate_offer

        validate_offer(item, facts)
        return
    if item.kind == "NETWORK_TLS_SESSION":
        from shared_models.tls_session import validate_session

        validate_session(item, facts)
        return
    if item.kind in {"OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"}:
        from shared_models.oci_content import validate_container

        validate_container(item, facts)
        return
    if item.kind == "OCI_IMAGE_METADATA":
        from shared_models.oci_image import validate_image

        validate_image(item, facts)
        return
    selected = resource(item.kind, item.path)
    if selected is None:
        return
    if item.kind == "WINDOWS_CAPI_DEFAULT_PROVIDER":
        from shared_models.windows_capi import validate_provider

        validate_provider(item, facts)
        return
    if item.kind == "WINDOWS_TCP_LISTENERS":
        from shared_models.windows_listeners import validate_listeners

        validate_listeners(item, facts)
        return
    if item.kind == "WINDOWS_TPM_DEVICE_INFO":
        from shared_models.windows_tpm import validate_device

        validate_device(item, facts)
        return
    if item.kind == "WINDOWS_CNG_REGISTRATION":
        from shared_models.windows_cng import validate_registration

        validate_registration(item, facts)
        return
    if item.kind == "WINDOWS_PROCESS_MODULES":
        from shared_models.windows_images import validate_images

        validate_images(item, facts)
        return
    if item.kind == "WINDOWS_CERTIFICATE":
        if facts and (len(facts) != 1 or facts[0].kind != "CERTIFICATE" or facts[0].fingerprint_sha256 != selected[3]):
            raise ValueError("Certificate observation does not match approved SHA-256")
        return
    if len({f.identity_key for f in facts}) != len(facts):
        raise ValueError("Duplicate runtime subject within one approved input")
    for fact in facts:
        if item.kind in {"LINUX_PROCESS", "LINUX_PROCESS_MAPS"}:
            if fact.interface != "LINUX_PROCFS" or selected != "self" and fact.pid != int(selected):
                raise ValueError("Process observation is outside approved PID")
        if item.kind == "LINUX_LISTENERS" and fact.transport != ("TCP6" if selected == "tcp6" else "TCP"):
            raise ValueError("Listener address family is outside scope")
        if item.kind in {"LINUX_SERVICE", "WINDOWS_SERVICE"}:
            interface = "SYSTEMD_READ_ONLY" if item.kind == "LINUX_SERVICE" else "WINDOWS_SCM"
            if fact.service_name != selected or fact.interface != interface:
                raise ValueError("Service observation is outside scope")
        if item.kind == "LINUX_HARDWARE" and (
            fact.hardware_type
            != ("SYSTEM_DMI" if selected == "dmi" else "CPU_TOPOLOGY" if selected.startswith("cpu") else "TPM")
            or fact.identity_key != selected
        ):
            raise ValueError("Hardware observation is outside scope")

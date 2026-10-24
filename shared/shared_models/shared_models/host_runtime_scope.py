"""Canonical interface resources and fact-to-approved-resource consistency."""

import re


def resource(kind, path):
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
    selected = resource(item.kind, item.path)
    if selected is None:
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

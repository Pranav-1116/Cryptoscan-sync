"""Bounded literal Linux package metadata, never executes package tools/scripts."""

from shared_models.host_collection import HostFact, MAX_FACTS


def apk_installed(data):
    from inventory.host import Refused

    facts = []
    names = set()
    for record in data.decode("utf-8").strip().split("\n\n"):
        values = {}
        for line in record.splitlines():
            if not line:
                continue
            if len(line) < 2 or line[1] != ":":
                raise ValueError("Invalid APK installed record")
            if line[0] in {"P", "V"}:
                if line[0] in values:
                    raise ValueError("Ambiguous APK field")
                values[line[0]] = line[2:]
        if set(values) != {"P", "V"} or not all(values.values()) or values["P"] in names:
            raise ValueError("Missing or duplicate APK identity")
        names.add(values["P"])
        facts.append(
            HostFact(
                kind="SOFTWARE",
                local_basis="OBSERVED",
                purpose="PACKAGE_DATABASE_RECORD",
                software_name=values["P"],
                software_version=values["V"],
            )
        )
        if len(facts) > MAX_FACTS:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
    if not facts:
        raise ValueError("Empty installed database")
    return facts


def dpkg_status(data):
    """Read bounded literal Deb822 records, never invoke dpkg or maintainer code.

    An installed state is retained irrespective of selection (including hold or
    pending removal). Architecture is not represented by HostFact v1: duplicate
    package names therefore refuse rather than merging multiarch identities.
    """
    import re
    from inventory.host import Refused
    from shared_models.host_collection import MAX_FILE_BYTES

    if not data:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    if len(data) > MAX_FILE_BYTES:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    text = data.decode("utf-8").replace("\r\n", "\n")
    if "\r" in text or "\x00" in text:
        raise ValueError("Invalid package database framing")
    facts, names = [], set()
    for stanza in re.split(r"\n\n+", text.strip("\n")):
        values = {}
        previous = None
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                if previous is None or previous in {"package", "version", "status", "architecture"}:
                    raise ValueError("Ambiguous package identity continuation")
                continue
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)", line)
            if not match:
                raise ValueError("Invalid package field")
            key, value = match.group(1).lower(), match.group(2)
            if key in values:
                raise ValueError("Duplicate package field")
            values[key] = value
            previous = key
        name, state = values.get("package", ""), values.get("status", "").split()
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) or len(state) != 3:
            raise ValueError("Missing package identity/status")
        if (
            state[0] not in {"unknown", "install", "hold", "deinstall", "purge"}
            or state[1] not in {"ok", "reinstreq"}
            or state[2]
            not in {
                "not-installed",
                "config-files",
                "half-installed",
                "unpacked",
                "half-configured",
                "triggers-awaited",
                "triggers-pending",
                "installed",
            }
        ):
            raise ValueError("Unsupported package status")
        if name in names:
            raise ValueError("Ambiguous duplicate/multiarch package identity")
        names.add(name)
        if state[2] != "installed":
            continue
        version = values.get("version")
        if version is not None and not version:
            raise ValueError("Empty package version")
        facts.append(
            HostFact(
                kind="SOFTWARE",
                local_basis="OBSERVED",
                purpose="PACKAGE_DATABASE_RECORD",
                software_name=name,
                software_version=version,
            )
        )
        if len(facts) > MAX_FACTS:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
    if not facts:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    return facts

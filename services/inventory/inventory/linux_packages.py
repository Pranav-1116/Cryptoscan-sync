"""Bounded literal Alpine installed-database profile, never executes apk/scripts."""

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

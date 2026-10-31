"""The five things this build does not do, in the sentences the product owes a bank.

Everything elsewhere in the tree describes what *is* there. This module is the
opposite list, and it is deliberately short and machine-read, because the failure
mode it prevents is not a bug: it is a deck, a demo or a support call in which a
capability that is *modelled* is heard as a capability that is *operational*.

The distinctions, stated plainly:

* **Windows collector** — a candidate implementation, not a production collector.
* **Hardware discovery** — synthetic and metadata paths, not complete hardware
  discovery across a bank's estate.
* **HSM** — a metadata model (vendor, model, firmware, algorithm capability, key
  metadata, certificate relationships). It is not proof of cryptographic
  operations performed inside the device.
* **Runtime crypto** — process, binary, library and service metadata. That is not
  evidence that a process actually invoked AES-256-GCM.
* **Simulation** — a PQC migration foundation plus nine scenario-specific models.
  It is not a generic enterprise simulation engine.

Each entry names the *real* thing it is not, the register area it belongs to
(``shared_models/maturity_register.py``), and the route that lets a reader check
the claim instead of taking it on trust. ``test_capability_boundaries`` fails if a
sentence stops matching the register, so the doc, the console and the code cannot
drift apart.
"""

from __future__ import annotations

SCHEMA = "cryptoscan.capability-boundaries/1"

#: The one-line form shown next to the capability in the console and the docs.
STATEMENTS: tuple[dict, ...] = (
    {
        "id": "WINDOWS_COLLECTOR",
        "area": "WINDOWS",
        "capability": "Windows collector",
        "status": "CANDIDATE",
        "says": (
            "Windows support is a candidate implementation, not a production collector: "
            "no universal Windows admission and no complete collector."
        ),
        "not_operational": (
            "a production Windows cryptographic collector, or complete Windows SBOM, NBOM, "
            "HBOM, VBOM and TechBOM coverage"
        ),
        "what_is_real": (
            "candidate collectors for OS/uninstall/file/SCM, public certificates, "
            "process/module inventory and TPM device info, with the server's own layer-by-layer NO"
        ),
        "check_at": "/estate/evidence/discovery/windows-collector",
    },
    {
        "id": "HARDWARE_DISCOVERY",
        "area": "HARDWARE_HSM",
        "capability": "Hardware discovery",
        "status": "FOUNDATION",
        "says": (
            "Hardware discovery is partial: it walks synthetic and metadata paths, so the "
            "product does not perform complete hardware discovery."
        ),
        "not_operational": "complete hardware discovery across a bank estate",
        "what_is_real": (
            "a vendor/model/firmware catalogue and plugin seam, fed where a vendor exposes "
            "metadata and by synthetic paths where it does not"
        ),
        "check_at": "/estate/evidence/discovery/maturity",
    },
    {
        "id": "HSM_OPERATIONS",
        "area": "HARDWARE_HSM",
        "capability": "HSM",
        "status": "FOUNDATION",
        "says": (
            "The HSM model is metadata — vendor, model, firmware, algorithm capability, key "
            "metadata and certificate relationships. It is not proof of actual HSM "
            "cryptographic operations."
        ),
        "not_operational": (
            "proof that a key operation ran inside an HSM, or key custody and key-use assurance"
        ),
        "what_is_real": (
            "a PKCS#11 seam for signing, and metadata plus certificate relationships for the "
            "assets that depend on a custodian"
        ),
        "check_at": "/estate/evidence/discovery/maturity",
    },
    {
        "id": "RUNTIME_INVOCATION",
        "area": "RUNTIME_DISCOVERY",
        "capability": "Runtime crypto",
        "status": "CANDIDATE",
        "says": (
            "Runtime discovery establishes process, binary, library and service metadata. That "
            "does not establish that a process actually invoked AES-256-GCM, and the platform "
            "never presents the two as the same fact."
        ),
        "not_operational": "proof of which algorithms a process executed",
        "what_is_real": (
            "processes, libraries, listeners, services, packages, certificates and configuration, "
            "each carrying the evidence class that produced it"
        ),
        "check_at": "/estate/evidence/discovery/runtime-depth",
    },
    {
        "id": "SIMULATION_ENGINE",
        "area": "SIMULATION_ENGINE",
        "capability": "Simulation",
        "status": "FOUNDATION",
        "says": (
            "The simulation foundation is real for PQC migration. The generic enterprise engine "
            "— TLS downgrade, certificate compromise, HSM failure, KMS failure, crypto-library "
            "compromise, supply-chain compromise, trust compromise, service compromise and "
            "custom scenario — is not fully implemented, and the product says which of them "
            "compute and which do not."
        ),
        "not_operational": (
            "a generic enterprise simulation engine that answers arbitrary what-if questions "
            "across every crypto failure mode"
        ),
        "what_is_real": (
            "ten deterministic scenarios and three cascades over collected evidence, plus a "
            "per-scenario statement of what each one cannot see"
        ),
        "check_at": "/estate/evidence/twin/simulation-scenarios",
    },
)


def statements() -> list[dict]:
    """The boundaries, copied so a caller cannot rewrite the module-level list."""
    return [dict(row) for row in STATEMENTS]


def boundaries() -> dict:
    return {
        "schema": SCHEMA,
        "statements": statements(),
        "note": (
            "Each row names the capability that is real and the capability that is not. A "
            "capability on this list may be demonstrated; it may not be sold as operational."
        ),
    }


def by_area() -> dict[str, list[dict]]:
    """Grouped by register area, for rendering beside the register's own rows."""
    grouped: dict[str, list[dict]] = {}
    for row in STATEMENTS:
        grouped.setdefault(row["area"], []).append(dict(row))
    return grouped


__all__ = ["SCHEMA", "STATEMENTS", "boundaries", "by_area", "statements"]

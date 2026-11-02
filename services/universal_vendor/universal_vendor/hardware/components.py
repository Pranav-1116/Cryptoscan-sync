"""The component inventory: what a host actually contains, kind by kind.

The review drew a distinction this module exists to enforce:

    host collection ≠ complete hardware scanner

A host collector that reports a DMI blob, a disk list and a NIC list has collected
*some* facts. It has not answered "what hardware does this machine have?" — for
that you need every component class a bank audits (CPU, memory, mainboard, BIOS,
firmware, PCI, GPU, NIC, storage controller, disk, RAID, TPM, HSM, smart card,
crypto accelerator) with a status per class, and — the part that is usually
missing — an explicit difference between:

``PRESENT``  the reader looked and found it, and here is what it found;
``ABSENT``   the reader looked, and this machine does not have one;
``UNKNOWN``  nobody looked, or the look failed — and here is the reason.

Collapsing ``UNKNOWN`` into ``ABSENT`` is how an estate ends up reporting "no GPU,
no TPM, no crypto accelerator" on a machine whose collector was simply
unprivileged. Every component therefore carries a ``source`` and, when it is not
present, a ``reason`` a reader can act on.

This is a *projection*, not a second store. The inputs are the facts the host
readers already produce (``host/linux.py``, ``host/windows.py``) plus the
security-hardware records the HSM/TPM readers produce; this module stores
nothing and owns no table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

SCHEMA = "cryptoscan.hardware-components/1"

PRESENT, ABSENT, UNKNOWN = "PRESENT", "ABSENT", "UNKNOWN"

#: Every component class the review asked to see covered, in the order it named
#: them. A class outside this tuple is not reportable: the inventory is graded
#: against this list, so adding a class is a reviewable act.
COMPONENT_KINDS: tuple[str, ...] = (
    "cpu", "memory", "motherboard", "bios", "firmware", "pci", "gpu", "nic",
    "storage_controller", "disk", "raid", "tpm", "hsm", "smart_card",
    "crypto_accelerator",
)

#: PCI class code -> component kind. The codes are the PCI-SIG base/sub classes;
#: a device whose code is not here is still listed under ``pci`` but is not
#: claimed as a component kind.
PCI_CLASS_KINDS: dict[str, str] = {
    "0200": "nic", "0280": "nic",
    "0300": "gpu", "0301": "gpu", "0302": "gpu", "0380": "gpu",
    "0104": "raid", "0105": "raid",
    "0106": "storage_controller", "0107": "storage_controller",
    # 0b40 is "Processing accelerators: Coprocessor"; 1080 is "Encryption
    # controller"; 1200 is "Processing accelerators".
    "0b40": "crypto_accelerator", "1080": "crypto_accelerator", "1200": "crypto_accelerator",
}

#: Kinds whose facts come from a dedicated security-hardware reader rather than
#: from the host reader. The host reader is not asked to open a TPM.
SECURITY_KINDS = ("tpm", "hsm", "smart_card", "crypto_accelerator")

_CLASS_CODE = re.compile(r"\[([0-9a-fA-F]{4})\]")


class UnknownPlatform(ValueError):
    """The facts handed in are not a shape this projection understands."""


def pci_class_code(value: Any) -> str | None:
    """``"VGA compatible controller [0300]"`` -> ``"0300"``.

    ``lspci -nnmm`` appends the numeric class in brackets; taking the *last*
    bracket keeps a device name that itself contains brackets from being read as
    a class code.
    """
    if not value:
        return None
    found = _CLASS_CODE.findall(str(value))
    return found[-1].lower() if found else None


def classify_pci(value: Any) -> str | None:
    """The component kind a PCI class string denotes, if any."""
    code = pci_class_code(value)
    if code is None:
        return None
    return PCI_CLASS_KINDS.get(code) or PCI_CLASS_KINDS.get(code[:2] + "00")


@dataclass
class Component:
    """One component class on one asset."""

    kind: str
    status: str
    source: str
    name: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in COMPONENT_KINDS:
            raise ValueError(f"{self.kind!r} is not a reportable component kind")
        if self.status not in {PRESENT, ABSENT, UNKNOWN}:
            raise ValueError(f"{self.status!r} is not a component status")
        if self.status != PRESENT and not self.reason:
            # An absent-or-unknown component without a reason is an assertion.
            raise ValueError(f"{self.kind}: a non-present component must say why")

    def to_dict(self) -> dict[str, Any]:
        payload = {"kind": self.kind, "status": self.status, "source": self.source,
                   "name": self.name, "fields": dict(self.fields),
                   "evidence": list(self.evidence)}
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass
class ComponentInventory:
    """Every component kind for one asset, each with a status and a provenance."""

    asset_id: str
    platform: str
    components: list[Component] = field(default_factory=list)
    inputs: dict[str, str] = field(default_factory=dict)

    #: A stronger answer wins over a weaker one for the same kind. If PCI found a
    #: crypto accelerator and the vendor reader did not run, the component is
    #: PRESENT from PCI — not UNKNOWN because the second reader stayed silent.
    _RANK = {PRESENT: 2, ABSENT: 1, UNKNOWN: 0}

    def add(self, component: Component) -> None:
        existing = self.by_kind().get(component.kind)
        if existing is None:
            self.components.append(component)
            return
        if self._RANK[component.status] > self._RANK[existing.status]:
            self.components[self.components.index(existing)] = component
            return
        if component.status == PRESENT and existing.status == PRESENT:
            merged = Component(
                kind=component.kind, status=PRESENT,
                source=f"{existing.source} + {component.source}",
                name=existing.name or component.name,
                fields={**component.fields, **existing.fields},
                evidence=sorted({*existing.evidence, *component.evidence}))
            self.components[self.components.index(existing)] = merged

    def by_kind(self) -> dict[str, Component]:
        return {component.kind: component for component in self.components}

    def statuses(self) -> dict[str, str]:
        """One status per required kind; a kind nobody reported is UNKNOWN."""
        found = self.by_kind()
        return {kind: found[kind].status if kind in found else UNKNOWN
                for kind in COMPONENT_KINDS}

    @property
    def present(self) -> list[str]:
        return [kind for kind, status in self.statuses().items() if status == PRESENT]

    @property
    def gaps(self) -> list[dict[str, str]]:
        found = self.by_kind()
        return [{"kind": kind, "status": status,
                 "reason": found[kind].reason if kind in found else "no reader reported it"}
                for kind, status in self.statuses().items() if status != PRESENT]

    @property
    def complete(self) -> bool:
        """True only when every required kind was actually looked for."""
        return not any(status == UNKNOWN for status in self.statuses().values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "asset_id": self.asset_id,
            "platform": self.platform,
            "components": [component.to_dict() for component in self.components],
            "statuses": self.statuses(),
            "present": self.present,
            "gaps": self.gaps,
            "complete": self.complete,
            "inputs": dict(self.inputs),
        }


def _reason_for(context: Mapping[str, Any], needle: str) -> str:
    for reason in context.get("unavailable") or ():
        if needle.lower() in str(reason).lower():
            return str(reason)
    return "the reader did not supply this fact"


def _have(context: Mapping[str, Any], key: str) -> bool:
    return bool(context.get(key))


def _record(*, kind: str, present: bool, source: str, name: str | None = None,
            fields: Mapping[str, Any] | None = None, evidence: list[str] | None = None,
            absent_reason: str, unknown_reason: str | None = None,
            looked: bool = True) -> Component:
    """Build a component, deciding PRESENT / ABSENT / UNKNOWN explicitly."""
    if present:
        return Component(kind=kind, status=PRESENT, source=source, name=name,
                         fields=dict(fields or {}), evidence=list(evidence or []))
    if looked and not unknown_reason:
        return Component(kind=kind, status=ABSENT, source=source, reason=absent_reason)
    return Component(kind=kind, status=UNKNOWN, source=source,
                     reason=unknown_reason or absent_reason)


# --------------------------------------------------------------------------- #
# Linux facts -> components
# --------------------------------------------------------------------------- #

def from_linux(context: Mapping[str, Any], *,
               security_hardware: Mapping[str, Any] | None = None) -> ComponentInventory:
    """Project a ``LinuxHostCollector`` context onto the component kinds."""
    if "dmi" not in context and "pci_devices" not in context:
        raise UnknownPlatform("this is not a Linux host context")
    inventory = ComponentInventory(asset_id=str(context.get("asset_id") or ""),
                                   platform="linux")
    inventory.inputs.update({key: str(value) for key, value in
                             (context.get("sources") or {}).items()})

    dmi = dict(context.get("dmi") or {})
    cpu = dict(context.get("cpu") or {})
    inventory.add(_record(
        kind="cpu", present=bool(cpu), source="lscpu",
        name=cpu.get("model name") or cpu.get("model"),
        fields={key: cpu[key] for key in ("model name", "vendor id", "cpu(s)",
                                          "core(s) per socket", "socket(s)",
                                          "virtualization") if key in cpu},
        evidence=["lscpu"] if cpu else [],
        absent_reason="the host reports no processor",
        unknown_reason=None if cpu else _reason_for(context, "lscpu")))

    memory = list(context.get("memory_modules") or [])
    inventory.add(_record(
        kind="memory", present=bool(memory), source="dmidecode -t memory",
        name=f"{len(memory)} module(s)",
        fields={"modules": memory, "total_mb": context.get("memory_total_mb")},
        evidence=["dmidecode -t memory"] if memory else [],
        absent_reason="no memory devices are populated",
        unknown_reason=None if memory else _reason_for(context, "dmidecode -t memory")))

    inventory.add(_record(
        kind="motherboard", present=bool(dmi.get("board")), source="dmi:board_name",
        name=dmi.get("board"),
        fields={"board": dmi.get("board"), "manufacturer": dmi.get("manufacturer")},
        evidence=["sysfs:dmi/board_name"] if dmi.get("board") else [],
        absent_reason="the DMI table names no mainboard",
        unknown_reason=None if dmi.get("board") else _reason_for(context, "dmi")))

    inventory.add(_record(
        kind="bios", present=bool(dmi.get("bios_version")), source="dmi:bios_version",
        name=dmi.get("bios_version"),
        fields={"version": dmi.get("bios_version"), "date": dmi.get("bios_date")},
        evidence=["sysfs:dmi/bios_version"] if dmi.get("bios_version") else [],
        absent_reason="the DMI table names no BIOS version",
        unknown_reason=None if dmi.get("bios_version") else _reason_for(context, "dmi")))

    # Firmware is not one component: it is the version of each component that has
    # one. Reporting "firmware: present" with nothing in it is the failure mode.
    firmware = {}
    if dmi.get("bios_version"):
        firmware["bios"] = dmi.get("bios_version")
    for disk in context.get("disks") or ():
        if disk.get("firmware"):
            firmware[f"disk:{disk.get('device') or disk.get('model')}"] = disk["firmware"]
    for nic in context.get("nics") or ():
        if nic.get("firmware"):
            firmware[f"nic:{nic.get('name')}"] = nic["firmware"]
    inventory.add(_record(
        kind="firmware", present=bool(firmware), source="dmi + lsblk + sysfs",
        name=f"{len(firmware)} component(s)",
        fields={"revisions": firmware},
        evidence=sorted(firmware), absent_reason="no component reported a firmware revision",
        unknown_reason=None if firmware else "no firmware revision was readable"))

    pci = list(context.get("pci_devices") or ())
    pci_looked = "pci_devices" in (context.get("sources") or {}) or bool(pci)
    inventory.add(_record(
        kind="pci", present=bool(pci), source="lspci -nnmm", name=f"{len(pci)} device(s)",
        fields={"devices": pci}, evidence=["lspci"] if pci else [],
        absent_reason="the PCI bus reported no devices",
        unknown_reason=None if pci_looked else _reason_for(context, "lspci"),
        looked=pci_looked))

    def pci_kind(kind: str) -> list[dict[str, Any]]:
        return [device for device in pci if classify_pci(device.get("class")) == kind]

    for kind, what in (("gpu", "display controller"),
                       ("raid", "RAID controller"),
                       ("storage_controller", "storage controller"),
                       ("crypto_accelerator", "crypto/processing accelerator")):
        matches = pci_kind(kind)
        inventory.add(_record(
            kind=kind, present=bool(matches), source="lspci -nnmm",
            name=matches[0].get("device") if matches else None,
            fields={"devices": matches} if matches else {},
            evidence=[f"pci:{device.get('slot')}" for device in matches],
            absent_reason=f"no PCI {what} is present",
            unknown_reason=None if pci_looked else (
                _reason_for(context, "lspci") or "the PCI bus was not enumerated"),
            looked=pci_looked))

    nics = list(context.get("nics") or ())
    inventory.add(_record(
        kind="nic", present=bool(nics), source="sysfs:/sys/class/net",
        name=f"{len(nics)} interface(s)", fields={"interfaces": nics},
        evidence=[f"sysfs:net/{nic.get('name')}" for nic in nics],
        absent_reason="the host has no network interface beyond loopback",
        unknown_reason=None if nics else _reason_for(context, "net"),
        looked=bool(nics) or "nics" in (context.get("sources") or {})))

    disks = list(context.get("disks") or ())
    inventory.add(_record(
        kind="disk", present=bool(disks), source="lsblk --json + smartctl",
        name=f"{len(disks)} disk(s)", fields={"disks": disks},
        evidence=[f"lsblk:{disk.get('device')}" for disk in disks],
        absent_reason="the host reports no block device",
        unknown_reason=None if disks else _reason_for(context, "lsblk"),
        looked=bool(disks) or "disks" in (context.get("sources") or {})))

    # The security-hardware kinds are not the host reader's job: a host collector
    # that opens a TPM is a collector with more privilege than it needs.
    for kind in SECURITY_KINDS:
        inventory.add(_security_component(kind, (security_hardware or {}).get(kind)))
    return inventory


# --------------------------------------------------------------------------- #
# Windows facts -> components
# --------------------------------------------------------------------------- #

def from_windows(context: Mapping[str, Any], *,
                 security_hardware: Mapping[str, Any] | None = None) -> ComponentInventory:
    """Project a ``WindowsHostCollector`` context onto the component kinds."""
    if "platform" not in context and "processors" not in context:
        raise UnknownPlatform("this is not a Windows host context")
    inventory = ComponentInventory(asset_id=str(context.get("asset_id") or ""),
                                   platform="windows")
    inventory.inputs.update({key: str(value) for key, value in
                             (context.get("sources") or {}).items()})

    processors = list(context.get("processors") or ())
    inventory.add(_record(
        kind="cpu", present=bool(processors), source="cim:Win32_Processor",
        name=processors[0].get("name") if processors else None,
        fields={"processors": processors},
        evidence=["cim:Win32_Processor"] if processors else [],
        absent_reason="the host reports no processor",
        unknown_reason=None if processors else _reason_for(context, "Win32_Processor")))

    # Windows reports a memory *total* from Win32_ComputerSystem and module detail
    # only through Win32_PhysicalMemory, which is not in the allowlist yet. Saying
    # so is better than reporting a total and calling the modules collected.
    total = context.get("memory_total_mb")
    inventory.add(_record(
        kind="memory", present=bool(total), source="cim:Win32_ComputerSystem",
        name=f"{total} MB" if total else None,
        fields={"total_mb": total,
                "modules": "not read: Win32_PhysicalMemory is not on the CIM allowlist"},
        evidence=["cim:Win32_ComputerSystem"] if total else [],
        absent_reason="the host reports no physical memory",
        unknown_reason=None if total else _reason_for(context, "Win32_ComputerSystem")))

    board = dict((context.get("firmware") or {}))
    inventory.add(_record(
        kind="motherboard", present=bool(board.get("baseboard_product")),
        source="cim:Win32_BaseBoard", name=board.get("baseboard_product"),
        fields={"product": board.get("baseboard_product"),
                "version": board.get("baseboard_version")},
        evidence=["cim:Win32_BaseBoard"] if board.get("baseboard_product") else [],
        absent_reason="the baseboard class returned no product name",
        unknown_reason=None if board.get("baseboard_product")
        else _reason_for(context, "Win32_BaseBoard")))

    inventory.add(_record(
        kind="bios", present=bool(board.get("bios_version")), source="cim:Win32_BIOS",
        name=board.get("bios_version"),
        fields={"version": board.get("bios_version"),
                "release_date": board.get("bios_release_date"),
                "vendor": board.get("bios_vendor")},
        evidence=["cim:Win32_BIOS"] if board.get("bios_version") else [],
        absent_reason="the BIOS class returned no SMBIOSBIOSVersion",
        unknown_reason=None if board.get("bios_version") else _reason_for(context, "Win32_BIOS")))

    firmware = {}
    if board.get("bios_version"):
        firmware["bios"] = board["bios_version"]
    for disk in context.get("disks") or ():
        if disk.get("firmware"):
            firmware[f"disk:{disk.get('model')}"] = disk["firmware"]
    inventory.add(_record(
        kind="firmware", present=bool(firmware), source="cim:Win32_BIOS + Win32_DiskDrive",
        name=f"{len(firmware)} component(s)", fields={"revisions": firmware},
        evidence=sorted(firmware), absent_reason="no component reported a firmware revision",
        unknown_reason=None if firmware else "no firmware revision was readable"))

    # Windows does not enumerate PCI classes through an allowlisted CIM class. That
    # is a gap in the reader, not an absence of hardware, and it is reported as
    # UNKNOWN rather than as "this machine has no GPU".
    for kind, what in (("pci", "the PCI bus"), ("gpu", "a display controller"),
                       ("raid", "a RAID controller"),
                       ("storage_controller", "a storage controller"),
                       ("crypto_accelerator", "a crypto accelerator")):
        inventory.add(Component(
            kind=kind, status=UNKNOWN, source="not collected on Windows",
            reason=f"{what} is not enumerable through the current CIM allowlist: "
                   "Win32_PnPEntity and Win32_VideoController are not read"))

    inventory.add(Component(
        kind="nic", status=UNKNOWN, source="not collected on Windows",
        reason="Win32_NetworkAdapter is not on the CIM allowlist, so adapter "
               "count and firmware are unknown rather than zero"))

    disks = list(context.get("disks") or ())
    inventory.add(_record(
        kind="disk", present=bool(disks), source="cim:Win32_DiskDrive",
        name=f"{len(disks)} disk(s)", fields={"disks": disks},
        evidence=["cim:Win32_DiskDrive"] if disks else [],
        absent_reason="the host reports no disk drive",
        unknown_reason=None if disks else _reason_for(context, "Win32_DiskDrive")))

    supplied = dict(security_hardware or {})
    # On Windows the TPM *is* the host reader's job: Win32_Tpm is on the CIM
    # allowlist. An explicit record still wins if a TPM reader ran too.
    if "tpm" not in supplied and isinstance(context.get("tpm"), Mapping):
        tpm = dict(context["tpm"])
        supplied["tpm"] = {**tpm, "source": str((context.get("sources") or {}).get(
            "tpm") or "cim:Win32_Tpm")}
    for kind in SECURITY_KINDS:
        inventory.add(_security_component(kind, supplied.get(kind)))
    return inventory


# --------------------------------------------------------------------------- #
# security hardware kinds, from their own readers
# --------------------------------------------------------------------------- #

def _security_component(kind: str, facts: Any) -> Component:
    """A TPM/HSM/smart-card/accelerator component, or an honest UNKNOWN.

    ``facts`` is whatever the dedicated reader produced: a ``tpm`` module record,
    an ``HsmHardwareScanner`` observation, a PKCS#11 ``to_raw()`` dict. There is
    no attempt to interpret a shape this function does not recognise — an
    unrecognised record yields UNKNOWN with the reason, which is the whole point
    of the third state.
    """
    if not facts:
        return Component(kind=kind, status=UNKNOWN, source="no reader supplied it",
                         reason=f"no {kind} reader ran for this asset; absence is not "
                                "established by a collector that never looked")
    if not isinstance(facts, Mapping):
        return Component(kind=kind, status=UNKNOWN, source="unrecognised record",
                         reason=f"the {kind} reader produced {type(facts).__name__}, "
                                "which this projection does not interpret")
    present = facts.get("present")
    if present is False:
        return Component(kind=kind, status=ABSENT, source=str(facts.get("source") or kind),
                         reason=str(facts.get("reason") or f"the {kind} reader found none"))
    fields = {key: value for key, value in facts.items()
              if key in {"present", "version", "manufacturer", "firmware", "model",
                         "serial_reference", "cluster", "ha_state", "pqc_capabilities",
                         "supported_algorithms", "partition_metadata", "slots"}}
    if not fields:
        return Component(kind=kind, status=UNKNOWN, source="unrecognised record",
                         reason=f"the {kind} record carries no field this projection reads")
    return Component(kind=kind, status=PRESENT, source=str(facts.get("source") or kind),
                     name=str(facts.get("model") or facts.get("manufacturer") or kind),
                     fields=fields, evidence=[str(facts.get("evidence_id"))]
                     if facts.get("evidence_id") else [])

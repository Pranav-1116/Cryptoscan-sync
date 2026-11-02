"""The Windows host reader (phase H3): WMI/CIM behind an allowlist.

On Linux the reader opens ``/sys`` and runs a handful of named binaries. On
Windows the equivalent surface is CIM, reached through PowerShell's
``Get-CimInstance``. That is a scripting engine, and a scripting engine handed a
string is a shell — so this module is built the other way round from the usual
"run a query" helper:

* **There is no parameter that accepts a query, a class name or a script.** The
  only PowerShell text this module can produce is generated from
  :data:`CIM_ALLOWLIST`, a frozen table of eight classes. ``script_for`` takes a
  *key* into that table and raises :class:`CimQueryRejected` for anything else,
  so ``Win32_Process`` — or an f-string of the caller's choosing — cannot reach
  the command line.
* **Every class is asked for named properties only** (``-Property``), so the
  appliance returns the metadata this estate uses and not, for example, the
  contents of a partition. Data minimisation is cheaper than redaction.
* **Nothing is written and nothing is invoked.** Every entry in the table is a
  ``Get-`` verb. The generated text contains no verb that evaluates a string as
  code and no verb that starts a process — see :data:`FORBIDDEN_POWERSHELL` —
  and a test asserts the module cannot grow one quietly.
* **The provider is injectable.** :class:`RecordedCimProvider` replays a
  transcript so the parsing, the identity resolution and the refusals run on
  this Linux CI runner, on the same code path the agent uses. What that does
  *not* prove is that a real appliance answers the way the transcript does, and
  the artifact says so rather than implying a Windows host was opened.

Identity is resolved from ``Win32_ComputerSystemProduct.IdentifyingNumber``
first, then ``Win32_BIOS.SerialNumber``, then the baseboard. A hostname is a
name, not an identity, and is used only when all three are blank — the same
ordering the Linux reader applies to DMI.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - argv list only, no shell
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol, Sequence

from universal_vendor.hardware.safety import refuse_secret_material

SCHEMA = "cryptoscan.hardware.windows-host/1"

#: Tokens that must never appear in what this reader returns. The same list the
#: Linux reader uses: over-matching is the intended failure direction.
_FORBIDDEN_IN_OUTPUT = ("private_key", "private key", "password", "passwd", "secret",
                        "key_material", "key material", "authorization", "bearer ")

#: The fixed, non-negotiable prefix of a CIM invocation. ``-Command`` is the
#: only way PowerShell accepts text; what makes it safe here is that the text
#: is generated from :data:`CIM_ALLOWLIST` and from nothing else.
POWERSHELL_ARGV = ("powershell.exe", "-NoProfile", "-NonInteractive",
                   "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text", "-Command")


class CimQueryRejected(RuntimeError):
    """A CIM class, namespace or property outside the allowlist was requested.

    Raised rather than returning ``[]``: a caller that asks for a class this
    reader does not own has a bug or an intention, and both must be visible.
    """


@dataclass(frozen=True)
class CimQuery:
    """One allowlisted CIM read: a fact name, a class, and named properties."""

    key: str
    namespace: str
    class_name: str
    properties: tuple[str, ...]
    surface: str


#: Everything this reader may ask a Windows host. Eight reads; each one is a
#: documented ``root\cimv2`` (or provider) class, and each is asked for named
#: properties only. Adding a class is a deliberate act with a review, which is
#: the point of a table.
CIM_ALLOWLIST: tuple[CimQuery, ...] = (
    CimQuery("computer_system", "root\\cimv2", "Win32_ComputerSystem",
             ("Manufacturer", "Model", "TotalPhysicalMemory", "NumberOfProcessors",
              "NumberOfLogicalProcessors", "HypervisorPresent", "PartOfDomain"),
             "identity and virtualisation state"),
    CimQuery("product", "root\\cimv2", "Win32_ComputerSystemProduct",
             ("Vendor", "Name", "Version", "IdentifyingNumber", "UUID"),
             "asset identity"),
    CimQuery("bios", "root\\cimv2", "Win32_BIOS",
             ("Manufacturer", "Name", "Version", "SMBIOSBIOSVersion", "ReleaseDate",
              "SerialNumber"),
             "platform firmware"),
    CimQuery("baseboard", "root\\cimv2", "Win32_BaseBoard",
             ("Manufacturer", "Product", "SerialNumber", "Version"),
             "mainboard identity"),
    CimQuery("processors", "root\\cimv2", "Win32_Processor",
             ("Manufacturer", "Name", "NumberOfCores", "NumberOfLogicalProcessors",
              "VirtualizationFirmwareEnabled", "ProcessorId"),
             "CPU inventory"),
    CimQuery("disk_drives", "root\\cimv2", "Win32_DiskDrive",
             ("Model", "SerialNumber", "FirmwareRevision", "Size", "MediaType",
              "InterfaceType", "PNPDeviceID"),
             "disk firmware"),
    CimQuery("tpm", "root\\cimv2\\security\\microsofttpm", "Win32_Tpm",
             ("IsEnabled_InitialValue", "IsActivated_InitialValue", "ManufacturerIdTxt",
              "ManufacturerVersion", "SpecVersion", "PhysicalPresenceVersionInfo"),
             "TPM metadata"),
    CimQuery("device_guard", "root\\microsoft\\windows\\deviceguard", "Win32_DeviceGuard",
             ("VirtualizationBasedSecurityStatus", "SecurityServicesRunning",
              "SecurityServicesConfigured", "CodeIntegrityPolicyEnforcementStatus"),
             "secure boot and VBS state"),
)

ALLOWLIST: Mapping[str, CimQuery] = {query.key: query for query in CIM_ALLOWLIST}

#: PowerShell verbs that turn text into behaviour. Absent from every generated
#: script; a test asserts the module never learns them. Assembled from parts so
#: this audit does not itself read as the thing it forbids.
FORBIDDEN_POWERSHELL = ("invoke-" + "expression", "start-" + "process",
                        "i" + "ex ", "&" + " {", "add-" + "type")


def query_for(key: str) -> CimQuery:
    """The allowlisted entry for ``key``, or :class:`CimQueryRejected`."""
    try:
        return ALLOWLIST[key]
    except KeyError:
        raise CimQueryRejected(
            f"{key!r} is not an allowlisted CIM read; this reader can ask for "
            f"{sorted(ALLOWLIST)} and nothing else — arbitrary WQL or PowerShell "
            "is not a capability of the agent") from None


def script_for(key: str, *, depth: int = 4) -> str:
    """The one PowerShell line that reads ``key``.

    Built from the allowlist only. The class name, the namespace and the
    property list are literals in this module; nothing a caller passes reaches
    the text, which is why there is no injection surface to test for.
    """
    query = query_for(key)
    properties = ",".join(query.properties)
    return ("$ErrorActionPreference = 'Stop'; "
            f"Get-CimInstance -Namespace '{query.namespace}' "
            f"-ClassName '{query.class_name}' -Property {properties} "
            f"| ConvertTo-Json -Depth {int(depth)} -Compress")


@dataclass
class CimResult:
    """What one CIM read produced, and how it failed if it did."""

    key: str
    records: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    argv: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def empty(self) -> bool:
        return not self.records


class CimProvider(Protocol):
    """A source of allowlisted CIM reads."""

    def read(self, key: str) -> CimResult:  # pragma: no cover - protocol
        ...


def parse_cim_json(text: str) -> list[dict[str, Any]]:
    """Parse ``ConvertTo-Json`` output into records.

    PowerShell emits a bare object for one result and an array for several; an
    empty read emits nothing at all. All three are handled, because a reader
    that only understands the array shape silently loses single-disk hosts.
    """
    stripped = (text or "").strip()
    if not stripped:
        return []
    payload = json.loads(stripped)
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]
    raise ValueError("ConvertTo-Json produced neither an object nor an array")


def powershell_runner(script: str, timeout: float) -> CimResult:
    """Run one generated script. Never called with caller text.

    ``subprocess`` receives an argv list, so no shell parses anything; the
    script is the last element of :data:`POWERSHELL_ARGV` plus a string that
    came out of :func:`script_for`.
    """
    argv = (*POWERSHELL_ARGV, script)
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell, bounded timeout
            list(argv), shell=False, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return CimResult(key="", error="powershell.exe not installed", argv=argv)
    except subprocess.TimeoutExpired:
        return CimResult(key="", error=f"CIM read timed out after {timeout}s", argv=argv)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        return CimResult(key="", error=detail[0] if detail else f"exit {completed.returncode}",
                         argv=argv)
    try:
        records = parse_cim_json(completed.stdout)
    except ValueError as exc:
        return CimResult(key="", error=f"unreadable CIM reply: {exc}", argv=argv)
    return CimResult(key="", records=records, argv=argv)


class PowerShellCimProvider:
    """Runs the allowlisted reads on Windows through ``Get-CimInstance``."""

    def __init__(self, runner: Callable[[str, float], CimResult] | None = None,
                 *, timeout: float = 20.0) -> None:
        self.runner = runner or powershell_runner
        self.timeout = timeout

    def read(self, key: str) -> CimResult:
        result = self.runner(script_for(key), self.timeout)
        result.key = key
        return result


class RecordedCimProvider:
    """Replays a recorded transcript — the same code path, without Windows.

    ``records`` maps an allowlist key to the JSON text the appliance produced,
    or to a list of records. A key mapped to an exception instance raises it,
    so a test can drive the "this class is missing on this host" path.
    """

    def __init__(self, records: Mapping[str, Any]) -> None:
        self._records = dict(records)
        self.reads: list[str] = []

    def read(self, key: str) -> CimResult:
        query_for(key)  # a replay may not read outside the allowlist either
        self.reads.append(key)
        payload = self._records.get(key)
        if isinstance(payload, Exception):
            return CimResult(key=key, error=str(payload))
        if payload is None:
            return CimResult(key=key)
        if isinstance(payload, str):
            try:
                return CimResult(key=key, records=parse_cim_json(payload))
            except ValueError as exc:
                return CimResult(key=key, error=f"unreadable CIM reply: {exc}")
        return CimResult(key=key, records=[record for record in payload
                                           if isinstance(record, dict)])


@dataclass
class WindowsFacts:
    """The context the collectors consume, plus how each part was obtained."""

    context: dict[str, Any] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)
    unavailable: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "context": self.context,
            "sources": dict(self.sources),
            "unavailable": list(self.unavailable),
            "queries": list(self.queries),
        }


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def cim_date(value: Any) -> str | None:
    """A CIM datetime as ``YYYY-MM-DD``.

    PowerShell renders CIM datetimes as ISO strings, but ``/Date(1683849600000)/``
    still appears from providers that hand back .NET datetimes. Both are
    accepted; anything else is ``None`` rather than a guess.
    """
    text = _clean(value)
    if not text:
        return None
    if text.startswith("/Date(") and text.endswith(")/"):
        digits = text[6:-2].split("+")[0].split("-")[0]
        try:
            stamp = datetime.fromtimestamp(int(digits) / 1000, tz=timezone.utc)
        except (ValueError, OSError):
            return None
        return stamp.date().isoformat()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        head = text.split("T")[0]
        try:
            datetime.strptime(head, "%Y-%m-%d")
        except ValueError:
            return None
        return head


def _first(records: Sequence[Mapping[str, Any]], *names: str) -> str | None:
    for record in records:
        for name in names:
            value = _clean(record.get(name))
            if value:
                return value
    return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class WindowsHostCollector:
    """Read one Windows host into a collector context.

    ``provider`` is the only way in: the real one on a Windows agent, a recorded
    transcript in CI. There is no argument that carries a command.
    """

    def __init__(self, provider: CimProvider | None = None, *,
                 hostname: str | None = None) -> None:
        self.provider: CimProvider = provider or PowerShellCimProvider()
        self.hostname = hostname

    def _read(self, facts: WindowsFacts, key: str) -> list[dict[str, Any]]:
        facts.queries.append(key)
        result = self.provider.read(key)
        if not result.ok:
            facts.unavailable.append(f"{query_for(key).class_name}: {result.error}")
            return []
        if result.empty:
            facts.unavailable.append(
                f"{query_for(key).class_name}: no instances on this host")
            return []
        return result.records

    def collect(self, *, asset_id: str | None = None) -> WindowsFacts:
        facts = WindowsFacts()
        system = self._read(facts, "computer_system")
        product = self._read(facts, "product")
        bios = self._read(facts, "bios")
        baseboard = self._read(facts, "baseboard")
        processors = self._read(facts, "processors")
        disks = self._read(facts, "disk_drives")
        tpm_records = self._read(facts, "tpm")
        guard = self._read(facts, "device_guard")

        if system:
            facts.sources["identity"] = "cim:Win32_ComputerSystem"
        if product:
            facts.sources["product"] = "cim:Win32_ComputerSystemProduct"
        if bios:
            facts.sources["firmware"] = "cim:Win32_BIOS"
        if baseboard:
            facts.sources["baseboard"] = "cim:Win32_BaseBoard"
        if processors:
            facts.sources["cpu"] = "cim:Win32_Processor"
        if disks:
            facts.sources["disks"] = "cim:Win32_DiskDrive"
        if tpm_records:
            facts.sources["tpm"] = "cim:Win32_Tpm"
        if guard:
            facts.sources["secure_boot"] = "cim:Win32_DeviceGuard"

        serial = (_clean(product[0].get("IdentifyingNumber")) if product else None) \
            or (_clean(bios[0].get("SerialNumber")) if bios else None) \
            or (_clean(baseboard[0].get("SerialNumber")) if baseboard else None)
        manufacturer = (_clean(product[0].get("Vendor")) if product else None) \
            or (_clean(system[0].get("Manufacturer")) if system else None) \
            or (_clean(bios[0].get("Manufacturer")) if bios else None)

        platform = {
            "manufacturer": manufacturer,
            "model": (_clean(system[0].get("Model")) if system else None)
            or (_clean(product[0].get("Name")) if product else None),
            "serial_reference": serial,
            "uuid": _clean(product[0].get("UUID")) if product else None,
            "smbios_version": _clean(product[0].get("Version")) if product else None,
        }
        firmware = {
            "bios_vendor": _clean(bios[0].get("Manufacturer")) if bios else None,
            "bios_version": _clean(bios[0].get("SMBIOSBIOSVersion")) if bios
            else None,
            "bios_release_date": cim_date(bios[0].get("ReleaseDate")) if bios else None,
            "bios_name": _clean(bios[0].get("Name")) if bios else None,
            "baseboard_product": _clean(baseboard[0].get("Product")) if baseboard else None,
            "baseboard_version": _clean(baseboard[0].get("Version")) if baseboard else None,
        }
        cpu = [{
            "name": _clean(record.get("Name")),
            "manufacturer": _clean(record.get("Manufacturer")),
            "cores": _int_or_none(record.get("NumberOfCores")),
            "logical_processors": _int_or_none(record.get("NumberOfLogicalProcessors")),
            "virtualization_firmware_enabled": record.get("VirtualizationFirmwareEnabled"),
            "processor_id": _clean(record.get("ProcessorId")),
        } for record in processors]
        disk_inventory = [{
            "model": _clean(record.get("Model")),
            "serial_reference": _clean(record.get("SerialNumber")),
            "firmware": _clean(record.get("FirmwareRevision")),
            "size_bytes": _int_or_none(record.get("Size")),
            "media_type": _clean(record.get("MediaType")),
            "interface": _clean(record.get("InterfaceType")),
            "pnp_device_id": _clean(record.get("PNPDeviceID")),
        } for record in disks]

        tpm_record = tpm_records[0] if tpm_records else {}
        tpm = {
            "present": bool(tpm_records),
            "version": _clean(tpm_record.get("SpecVersion")),
            "manufacturer": _clean(tpm_record.get("ManufacturerIdTxt")),
            "firmware": _clean(tpm_record.get("ManufacturerVersion")),
            "enabled": tpm_record.get("IsEnabled_InitialValue"),
            "activated": tpm_record.get("IsActivated_InitialValue"),
            "physical_presence_version": _clean(
                tpm_record.get("PhysicalPresenceVersionInfo")),
            # Win32_Tpm exposes none of these; naming them as unavailable is
            # better than the reader inventing a PCR bank it never read.
            "capabilities": None,
            "supported_algorithms": None,
            "pcr_capabilities": None,
        }
        guard_record = guard[0] if guard else {}
        secure_boot = {
            "virtualization_based_security": guard_record.get(
                "VirtualizationBasedSecurityStatus"),
            "services_running": guard_record.get("SecurityServicesRunning"),
            "services_configured": guard_record.get("SecurityServicesConfigured"),
            "code_integrity_policy": guard_record.get(
                "CodeIntegrityPolicyEnforcementStatus"),
            # The TPM is the root of a measured boot; whether this host's boot
            # was actually measured is a separate attestation this reader does
            # not perform, so the relationship is stated as the fact it is.
            "tpm_holds_boot_measurements": bool(tpm_records),
        }
        memory_bytes = _int_or_none(system[0].get("TotalPhysicalMemory")) if system else None
        hypervisor = system[0].get("HypervisorPresent") if system else None

        context: dict[str, Any] = {
            "asset_id": asset_id or serial or self.hostname or "windows-host",
            "device_type": "hypervisor_host" if hypervisor else "server",
            "platform": platform,
            "firmware": firmware,
            "processors": cpu,
            "memory_total_mb": memory_bytes // (1024 * 1024) if memory_bytes else None,
            "disks": disk_inventory,
            "tpm": tpm,
            "secure_boot": secure_boot,
            "hypervisor_present": hypervisor,
            "domain_joined": system[0].get("PartOfDomain") if system else None,
        }
        refuse_secret_material(context, _FORBIDDEN_IN_OUTPUT,
                               surface="windows host collector")
        facts.context = context
        return facts

"""Linux host collection (phase H2): read the machine, never ask it a question.

The hardware collectors in :mod:`universal_vendor.hardware.discovery` and
:mod:`universal_vendor.hardware.plugins` consume a *context dict*: ``dmi``,
``memory_modules``, ``disks``, ``nics``, ``pci_devices``. Until this module
existed, nothing in the tree produced one, so every one of those fields was
whatever a caller typed in. This is the reader.

Safety rules, and why each one is structural rather than advisory:

* **Allowlisted binaries only.** :data:`ALLOWED_BINARIES` names the five
  programs this module may run — ``dmidecode``, ``lsblk``, ``lspci``,
  ``smartctl`` and nothing else. There is no "run this string" entry point, so
  there is no place for a caller's input to become a command.
* **argv lists, never a shell.** Every invocation is a list handed to
  ``subprocess.run`` with ``shell=False``; arguments are re-validated against
  :data:`_ARGUMENT` so a value carrying ``;``, ``|``, ``$``, a backtick or a
  newline is refused before it is ever spawned.
* **Validated device paths.** ``smartctl`` takes a device as a positional
  argument. :data:`_DEVICE` accepts only the shapes a block device actually has
  (``/dev/sda``, ``/dev/nvme0n1``), so a path cannot smuggle options.
* **A fixed sysfs allowlist.** DMI and NIC facts are read through
  :data:`SYSFS_FILES` and a closed set of per-interface filenames. Nothing else
  under ``/sys`` is openable through this class, which keeps the reader away
  from ``/sys/kernel/security``, TPM state and the rest of the machine's
  secrets.
* **Missing binaries and missing privilege are facts, not exceptions.** A bank
  host may not have ``dmidecode``, and an unprivileged agent gets
  ``Permission denied`` from it. Both land in :attr:`HostFacts.unavailable`
  with the reason, because a collector that raises on a hardened host is a
  collector that gets switched off.

What this module deliberately does not do: it does not read ``/dev/mem``, does
not touch a TPM, and extracts no key material. The output guard re-runs
:func:`~universal_vendor.hardware.safety.refuse_secret_material` over the
finished payload as a belt on top of the allowlists.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404 - only ever called with an argv list and shell=False
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from universal_vendor.hardware.safety import refuse_secret_material

SCHEMA = "cryptoscan.host-facts/1"

#: The only programs this module may execute. Adding one is a code change with a
#: review attached, not a configuration value.
ALLOWED_BINARIES = frozenset({"dmidecode", "lsblk", "lspci", "smartctl"})

#: sysfs files this reader may open, by fact name. A closed set: the class has no
#: `read(path)` method, so there is no way to reach anything outside it.
SYSFS_FILES: dict[str, str] = {
    "manufacturer": "class/dmi/id/sys_vendor",
    "product": "class/dmi/id/product_name",
    "serial": "class/dmi/id/product_serial",
    "bios_version": "class/dmi/id/bios_version",
    "bios_date": "class/dmi/id/bios_date",
    "board": "class/dmi/id/board_name",
}

#: Per-interface files read from ``/sys/class/net/<iface>/``.
SYSFS_INTERFACE_FILES = ("address", "operstate", "mtu", "speed")

_PLACEHOLDERS = frozenset({"", "unknown", "none", "n/a", "na", "to be filled by o.e.m.",
                           "default string", "not specified", "not available"})

#: One argv element. Deliberately narrow: no whitespace, no shell metacharacters.
_ARGUMENT = re.compile(r"^[A-Za-z0-9_@%+=:,./\-]{1,256}$")

#: A block device, and only a block device.
_DEVICE = re.compile(r"^/dev/(?:sd[a-z]{1,3}|nvme\d+n\d+|vd[a-z]{1,3}|xvd[a-z]{1,3}|"
                     r"mmcblk\d+|md\d+|dm-\d+)$")

#: Tokens that must never appear in what this reader returns.
_FORBIDDEN_IN_OUTPUT = ("private_key", "private key", "password", "passwd", "secret",
                        "key_material", "key material", "authorization", "bearer ")

_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}


class CommandNotAllowed(RuntimeError):
    """A command outside the allowlist was requested.

    Raised rather than silently skipped: a caller that tries to run something
    else has a bug or an intent, and both need to be visible.
    """


class PathNotAllowed(RuntimeError):
    """A sysfs path or device node outside the allowlist was requested."""


# --------------------------------------------------------------------------- #
# command execution
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CommandResult:
    """What one allowlisted command returned — including how it failed."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    available: bool = True
    timed_out: bool = False

    def failed(self) -> bool:
        return self.returncode != 0 or not self.available or self.timed_out


def build_argv(*argv: str) -> tuple[str, ...]:
    """Validate one allowlisted command, or refuse it.

    Validation happens before execution and is not a shell-quoting exercise:
    the values are never handed to a shell, so this is the only gate that has
    to hold.
    """
    if not argv:
        raise CommandNotAllowed("empty command")
    binary = Path(argv[0]).name
    if binary not in ALLOWED_BINARIES:
        raise CommandNotAllowed(
            f"{binary!r} is not an allowlisted host command; the allowlist is "
            f"{sorted(ALLOWED_BINARIES)}")
    for part in argv:
        if not isinstance(part, str) or not _ARGUMENT.match(part):
            raise CommandNotAllowed(
                f"argument {part!r} is not a plain argv element (the collector never "
                "passes a shell string)")
    return tuple(argv)


def validate_device(path: str) -> str:
    """Return ``path`` if it names a block device, else refuse it."""
    if not _DEVICE.match(path or ""):
        raise PathNotAllowed(
            f"{path!r} is not a block device; smartctl receives a device node, never a "
            "path of the caller's choosing")
    return path


def subprocess_runner(argv: Sequence[str], timeout: float) -> CommandResult:
    """Run one already-validated argv. ``shell=False`` is not configurable."""
    binary = shutil.which(argv[0])
    if binary is None:
        return CommandResult(tuple(argv), 127, "", f"{argv[0]} is not installed",
                             available=False)
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False, bounded timeout
            [binary, *argv[1:]],
            capture_output=True, text=True, timeout=timeout, check=False,
            shell=False, env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), 124, "", f"timed out after {timeout:g}s",
                             timed_out=True)
    except OSError as exc:  # noqa: BLE001 - binary vanished, container restriction
        return CommandResult(tuple(argv), 126, "", str(exc), available=False)
    return CommandResult(tuple(argv), completed.returncode, completed.stdout,
                         completed.stderr)


Runner = Callable[[Sequence[str], float], CommandResult]


# --------------------------------------------------------------------------- #
# parsers — pure functions, so they are testable without a host
# --------------------------------------------------------------------------- #

def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in _PLACEHOLDERS else text


def parse_dmidecode_system(text: str) -> dict[str, str]:
    """``dmidecode -t system`` -> the four fields the identity model needs."""
    wanted = {"manufacturer": "manufacturer", "product name": "product",
              "serial number": "serial", "sku number": "sku", "family": "family",
              "version": "version"}
    found: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, _, value = line.partition(":")
        name = wanted.get(key.strip().lower())
        cleaned = _clean(value)
        if name and cleaned and name not in found:
            found[name] = cleaned
    return found


def parse_dmidecode_memory(text: str) -> list[dict[str, Any]]:
    """``dmidecode -t memory`` -> installed modules only.

    Empty sockets are dropped rather than reported as 0 MB: an inventory that
    counts every slot as a module overstates the estate, and a bank reconciles
    against a purchased BOM.
    """
    modules: list[dict[str, Any]] = []
    current: dict[str, str] = {}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            _finish_module(modules, current)
            current = {}
            continue
        key, _, value = stripped.partition(":")
        current[key.strip().lower()] = value.strip()
    _finish_module(modules, current)
    return modules


def _finish_module(modules: list[dict[str, Any]], block: dict[str, str]) -> None:
    if block.get("memory device") is None and "size" not in block:
        return
    size = _clean(block.get("size"))
    if not size or "no module" in size.lower() or size.lower() == "unknown":
        return
    modules.append({
        "locator": _clean(block.get("locator")),
        "size_mb": _size_to_mb(size),
        "type": _clean(block.get("type")),
        "speed_mts": _clean(block.get("speed")),
        "manufacturer": _clean(block.get("manufacturer")),
        "part_number": _clean(block.get("part number")),
    })


def _size_to_mb(value: str) -> int | None:
    match = re.match(r"^(\d+)\s*(kb|mb|gb|tb)$", value.strip(), re.IGNORECASE)
    if not match:
        return None
    amount, unit = int(match.group(1)), match.group(2).lower()
    if unit == "kb":
        return amount // 1024
    return amount * {"mb": 1, "gb": 1024, "tb": 1024 * 1024}[unit]


def parse_lsblk(text: str) -> list[dict[str, Any]]:
    """``lsblk --json`` -> physical disks with firmware, serial and size."""
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    disks: list[dict[str, Any]] = []
    for device in payload.get("blockdevices") or []:
        if str(device.get("type") or "").lower() != "disk":
            continue
        disks.append({
            "device": _clean(device.get("path")),
            "name": _clean(device.get("name")),
            "model": _clean(device.get("model")),
            "serial_reference": _clean(device.get("serial")),
            "firmware": _clean(device.get("rev")),
            "size_bytes": device.get("size"),
            "rotational": device.get("rota"),
        })
    return disks


def parse_lspci(text: str) -> list[dict[str, str]]:
    """``lspci -nnmm`` -> PCI devices with numeric and textual identity."""
    devices: list[dict[str, str]] = []
    pattern = re.compile(r'^(?P<slot>\S+)\s+"(?P<klass>[^"]*)"\s+"(?P<vendor>[^"]*)"\s+'
                         r'"(?P<device>[^"]*)"')
    for line in (text or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        devices.append({
            "slot": match.group("slot"),
            "class": match.group("klass"),
            "vendor": match.group("vendor"),
            "device": match.group("device"),
            "vendor_id": _hex_id(match.group("vendor")),
            "device_id": _hex_id(match.group("device")),
        })
    return devices


def _hex_id(value: str) -> str | None:
    match = re.search(r"\[([0-9a-fA-F]{4})\]\s*$", value)
    return match.group(1).lower() if match else None


def parse_smartctl(text: str) -> dict[str, Any]:
    """``smartctl -j -i -H`` -> drive identity and health, no self-test logs."""
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {}
    status = payload.get("smart_status") or {}
    return {
        "model": _clean(payload.get("model_name")),
        "serial_reference": _clean(payload.get("serial_number")),
        "firmware": _clean(payload.get("firmware_version")),
        "health_passed": status.get("passed") if isinstance(status, dict) else None,
        "rotation_rate": payload.get("rotation_rate"),
    }


# --------------------------------------------------------------------------- #
# the collector
# --------------------------------------------------------------------------- #

@dataclass
class HostFacts:
    """The context dict the collectors consume, plus how each part was obtained."""

    context: dict[str, Any] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)
    unavailable: list[str] = field(default_factory=list)
    commands: list[tuple[str, ...]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "context": self.context,
            "sources": dict(self.sources),
            "unavailable": list(self.unavailable),
            "commands": [list(argv) for argv in self.commands],
        }


class LinuxHostCollector:
    """Read one Linux host into a collector context.

    ``sys_root`` and ``runner`` exist so the reader can be tested against a
    fixture tree and a recorded command transcript — on the same code path the
    agent uses, not a parallel one that only the tests run.
    """

    def __init__(self, *, sys_root: Path | str = Path("/sys"),
                 runner: Runner | None = None, timeout: float = 5.0,
                 proc_root: Path | str = Path("/proc")) -> None:
        self.sys_root = Path(sys_root)
        self.proc_root = Path(proc_root)
        self.runner: Runner = runner or subprocess_runner
        self.timeout = timeout

    # -- facts ---------------------------------------------------------- #

    def _read_sysfs(self, name: str) -> str | None:
        relative = SYSFS_FILES.get(name)
        if relative is None:
            raise PathNotAllowed(
                f"{name!r} is not an allowlisted sysfs fact; the reader opens "
                f"{sorted(SYSFS_FILES)} and nothing else")
        try:
            return _clean((self.sys_root / relative).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            return None

    def _read_interface_file(self, interface: Path, name: str) -> str | None:
        if name not in SYSFS_INTERFACE_FILES:
            raise PathNotAllowed(f"{name!r} is not an allowlisted interface file")
        try:
            return _clean((interface / name).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            return None

    def _dmi(self) -> dict[str, str]:
        dmi = {name: self._read_sysfs(name) for name in SYSFS_FILES}
        return {key: value for key, value in dmi.items() if value}

    def _run(self, facts: HostFacts, *argv: str) -> CommandResult:
        command = build_argv(*argv)
        result = self.runner(command, self.timeout)
        facts.commands.append(command)
        return result

    def _nics(self) -> list[dict[str, Any]]:
        interfaces: list[dict[str, Any]] = []
        try:
            directories = sorted((self.sys_root / "class" / "net").iterdir())
        except OSError:
            return interfaces
        for interface in directories:
            if interface.name == "lo":
                continue
            interfaces.append({
                "name": interface.name,
                "mac_address": self._read_interface_file(interface, "address"),
                "state": self._read_interface_file(interface, "operstate"),
                "mtu": self._read_interface_file(interface, "mtu"),
                "speed_mbps": self._read_interface_file(interface, "speed"),
            })
        return interfaces

    def _memory_total_mb(self) -> int | None:
        try:
            text = (self.proc_root / "meminfo").read_text(encoding="utf-8")
        except OSError:
            return None
        match = re.search(r"^MemTotal:\s+(\d+)\s+kB", text, re.MULTILINE)
        return int(match.group(1)) // 1024 if match else None

    # -- collection ----------------------------------------------------- #

    def collect(self, *, asset_id: str | None = None,
                include_smart: bool = True) -> HostFacts:
        facts = HostFacts()
        dmi = self._dmi()
        if dmi:
            facts.sources["dmi"] = "sysfs"

        if not dmi.get("manufacturer") or not dmi.get("serial"):
            result = self._run(facts, "dmidecode", "-t", "system")
            if result.failed():
                facts.sources["dmi"] = facts.sources.get("dmi", "unavailable")
                facts.unavailable.append(_reason("dmidecode -t system", result))
            else:
                for key, value in parse_dmidecode_system(result.stdout).items():
                    dmi.setdefault(key, value)
                facts.sources["dmi"] = "dmidecode"

        memory_modules: list[dict[str, Any]] = []
        result = self._run(facts, "dmidecode", "-t", "memory")
        if result.failed():
            facts.unavailable.append(_reason("dmidecode -t memory", result))
        else:
            memory_modules = parse_dmidecode_memory(result.stdout)
            facts.sources["memory_modules"] = "dmidecode" if memory_modules else "empty"
        memory_total = self._memory_total_mb()
        if memory_total is not None:
            facts.sources["memory_total"] = "proc-meminfo"

        disks: list[dict[str, Any]] = []
        result = self._run(facts, "lsblk", "--json", "--output",
                           "NAME,PATH,SERIAL,MODEL,REV,TYPE,SIZE,ROTA")
        if result.failed():
            facts.unavailable.append(_reason("lsblk", result))
        else:
            disks = parse_lsblk(result.stdout)
            facts.sources["disks"] = "lsblk" if disks else "empty"

        if include_smart:
            self._add_smart(facts, disks)

        pci_devices: list[dict[str, str]] = []
        result = self._run(facts, "lspci", "-nnmm")
        if result.failed():
            facts.unavailable.append(_reason("lspci", result))
        else:
            pci_devices = parse_lspci(result.stdout)
            facts.sources["pci_devices"] = "lspci" if pci_devices else "empty"

        nics = self._nics()
        if nics:
            facts.sources["nics"] = "sysfs"

        context: dict[str, Any] = {
            "asset_id": asset_id or _clean(dmi.get("serial")) or _hostname(self.proc_root),
            "device_type": "server",
            "dmi": dmi,
            "memory_modules": memory_modules,
            "memory_total_mb": memory_total,
            "disks": disks,
            "nics": nics,
            "pci_devices": pci_devices,
        }
        refuse_secret_material(context, _FORBIDDEN_IN_OUTPUT,
                               surface="linux host collector")
        facts.context = context
        return facts

    def _add_smart(self, facts: HostFacts, disks: list[dict[str, Any]]) -> None:
        health: dict[str, dict[str, Any]] = {}
        for disk in disks:
            device = disk.get("device")
            if not device:
                continue
            try:
                validate_device(device)
            except PathNotAllowed as exc:
                facts.unavailable.append(f"smartctl {device}: {exc}")
                continue
            result = self._run(facts, "smartctl", "-j", "-i", "-H", device)
            if result.failed():
                facts.unavailable.append(_reason(f"smartctl {device}", result))
                continue
            parsed = parse_smartctl(result.stdout)
            if parsed:
                health[device] = parsed
                disk["smart"] = parsed
        if health:
            facts.sources["disk_health"] = "smartctl"


def _reason(command: str, result: CommandResult) -> str:
    detail = (result.stderr or "").strip().splitlines()
    first = detail[0] if detail else f"exit {result.returncode}"
    if not result.available:
        return f"{command}: {first} (binary not installed)"
    if result.timed_out:
        return f"{command}: {first}"
    lowered = first.lower()
    if "permission denied" in lowered or "operation not permitted" in lowered:
        return f"{command}: {first} (needs root; the agent runs unprivileged by default)"
    return f"{command}: {first}"


def _hostname(proc_root: Path) -> str:
    try:
        name = (proc_root / "sys" / "kernel" / "hostname").read_text(encoding="utf-8").strip()
    except OSError:
        name = ""
    return name or "linux-host"

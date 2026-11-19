"""HBOM: the machine itself — platform, firmware, CPU, memory, disks, NICs, PCI, TPM.

Sources, in order of preference: sysfs (``/sys/class/dmi/id``, ``/sys/block``,
``/sys/class/net``, ``/sys/bus/pci``, ``/sys/class/tpm``), procfs (``cpuinfo``,
``meminfo``), and — only when present and permitted — ``dmidecode -t memory`` for
DIMM detail. Serial numbers and the platform UUID are root-only in sysfs; when the
agent is unprivileged they are reported as unavailable, never guessed.

Platform identity needs one authoritative source: the firmware (DMI) or, where the
platform exposes none (containers, many VMs, WSL), the bank's asset-register record
(:mod:`cryptava.register`). Register facts are sent as ``IMPORTED`` evidence; when both
exist they are cross-checked and a serial mismatch is reported, never resolved silently.
The plane is COMPLETE when identity is established and nothing readable was refused;
DIMM layout is only expected where the agent runs on the machine itself (inside a
container the node's memory modules are outside the workload's view by design).
"""

from __future__ import annotations

import os
import re
import socket
from typing import Any

from cryptava import __version__
from cryptava import register as asset_register
from cryptava.collectors import Context
from cryptava.observation import source
from cryptava.util import clean, run_allowed, slug

DMI_FIELDS = (
    "sys_vendor", "product_name", "product_version", "product_serial", "product_uuid",
    "product_family", "board_vendor", "board_name", "board_serial", "chassis_vendor",
    "chassis_type", "chassis_serial", "chassis_asset_tag", "bios_vendor", "bios_version",
    "bios_date", "bios_release",
)

CPU_CRYPTO_FLAGS = {
    "aes": "AES (AES-NI)",
    "vaes": "AES (VAES)",
    "sha_ni": "SHA-1/SHA-256 (SHA-NI)",
    "pclmulqdq": "GHASH/GCM (PCLMULQDQ)",
    "rdrand": "RDRAND (hardware RNG)",
    "rdseed": "RDSEED (hardware RNG)",
    # Arm
    "sha1": "SHA-1 (Armv8 crypto)",
    "sha2": "SHA-256 (Armv8 crypto)",
    "sha3": "SHA-3 (Armv8.2 crypto)",
    "sha512": "SHA-512 (Armv8.2 crypto)",
    "pmull": "GHASH/GCM (PMULL)",
    "sm3": "SM3 (Armv8.2 crypto)",
    "sm4": "SM4 (Armv8.2 crypto)",
}

PCI_VENDORS = {
    "0x8086": "Intel Corporation", "0x1022": "Advanced Micro Devices, Inc.",
    "0x10de": "NVIDIA Corporation", "0x14e4": "Broadcom Inc.", "0x15b3": "Mellanox Technologies",
    "0x1077": "QLogic (Marvell)", "0x1000": "Broadcom / LSI", "0x9005": "Microchip (Adaptec)",
    "0x1d0f": "Amazon.com, Inc.", "0x1af4": "Red Hat, Inc. (virtio)", "0x1414": "Microsoft Corporation",
    "0x15ad": "VMware, Inc.", "0x1ae0": "Google, Inc.", "0x19e5": "Huawei Technologies",
    "0x1924": "Solarflare (AMD)", "0x177d": "Cavium (Marvell)", "0x11ab": "Marvell Technology",
    "0x1b4b": "Marvell Technology", "0x144d": "Samsung Electronics", "0x1344": "Micron Technology",
    "0x1c5c": "SK hynix", "0x1b36": "Red Hat, Inc. (QEMU)", "0x1234": "QEMU", "0x80ee": "Oracle (VirtualBox)",
    "0x10ec": "Realtek Semiconductor", "0x1e0f": "KIOXIA", "0x15b7": "Western Digital (SanDisk)",
    "0x1987": "Phison Electronics", "0x103c": "Hewlett Packard Enterprise", "0x1028": "Dell Inc.",
    "0x1590": "Hewlett Packard Enterprise", "0x117c": "ATTO Technology", "0x1137": "Cisco Systems",
}

#: PCI classes worth an HBOM line (prefix match on the 6-hex-digit class code)
PCI_CLASSES = {
    "01": "storage controller",
    "02": "network controller",
    "03": "display / GPU",
    "0b40": "co-processor",
    "10": "encryption controller",
    "12": "processing accelerator",
}

INTEL_QAT_DEVICES = {"0x0435", "0x37c8", "0x19e2", "0x18ee", "0x18a0", "0x4940", "0x4942",
                     "0x4944", "0x6f54", "0x0443", "0x37c9", "0x19e3", "0x4941", "0x4943"}

VIRTUAL_PRODUCTS = (
    ("virtual machine", "Hyper-V"), ("vmware", "VMware"), ("kvm", "KVM"), ("qemu", "QEMU/KVM"),
    ("standard pc", "QEMU/KVM"), ("hvm domu", "Xen"), ("google compute engine", "GCE"),
    ("amazon ec2", "AWS Nitro"), ("virtualbox", "VirtualBox"), ("openstack", "OpenStack"),
)

CHASSIS_TYPES = {"1": "Other", "3": "Desktop", "9": "Laptop", "10": "Notebook", "17": "Main Server Chassis",
                 "23": "Rack Mount Chassis", "28": "Blade", "29": "Blade Enclosure", "1A": "Virtual"}


# --------------------------------------------------------------------------- #
# host naming
# --------------------------------------------------------------------------- #

def _hostname(ctx: Context) -> str:
    configured = clean(ctx.config.get("hostname"))
    if configured:
        return configured
    for candidate in (ctx.view.read_text("/etc/hostname", limit=256),
                      ctx.view.proc_text("sys/kernel/hostname", limit=256)):
        value = clean((candidate or "").splitlines()[0] if candidate else None)
        if value:
            return value
    return socket.gethostname() or "linux-host"


def _primary_ip(ctx: Context) -> str | None:
    configured = clean(ctx.config.get("primary_ip"))
    if configured:
        return configured
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # a UDP "connect" picks the source address of the default route; no packet is sent
            probe.connect(("10.255.255.255", 1))
            address = probe.getsockname()[0]
        finally:
            probe.close()
        if address and not address.startswith("127."):
            return address
    except OSError:
        pass
    addresses = _local_ipv4(ctx)
    return addresses[0] if addresses else None


def _local_ipv4(ctx: Context) -> list[str]:
    text = ctx.view.proc_text("net/fib_trie") or ""
    found: list[str] = []
    previous = None
    for line in text.splitlines():
        match = re.search(r"\|--\s+(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            previous = match.group(1)
            continue
        if "/32 host LOCAL" in line and previous and not previous.startswith("127."):
            if previous not in found:
                found.append(previous)
    return found


def _os_release(ctx: Context) -> dict[str, str]:
    text = ctx.view.read_text("/etc/os-release", limit=65536) or ctx.view.read_text("/usr/lib/os-release", limit=65536) or ""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _container_runtime(ctx: Context) -> str | None:
    if ctx.view.exists("/.dockerenv"):
        return "docker"
    if ctx.view.exists("/run/.containerenv"):
        return "podman"
    cgroup = ctx.view.proc_text("1/cgroup", limit=8192) or ""
    for marker in ("kubepods", "docker", "containerd", "libpod", "lxc"):
        if marker in cgroup:
            return marker
    return None


# --------------------------------------------------------------------------- #
# readers
# --------------------------------------------------------------------------- #

def _dmi(ctx: Context) -> tuple[dict[str, str], list[str]]:
    values: dict[str, str] = {}
    unreadable: list[str] = []
    for name in DMI_FIELDS:
        path = f"class/dmi/id/{name}"
        if not (ctx.view.sys / path).exists():
            continue
        value = ctx.view.sys_text(path)
        if value is None:
            unreadable.append(name)
            continue
        cleaned = clean(value)
        if cleaned:
            values[name] = cleaned
    return values, unreadable


def _cpuinfo(ctx: Context) -> dict[str, Any]:
    text = ctx.view.proc_text("cpuinfo", limit=4 * 1024 * 1024) or ""
    model = vendor = None
    flags: set[str] = set()
    logical = 0
    sockets: set[str] = set()
    implementer = None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "processor":
            logical += 1
        elif key in {"model name", "cpu model", "hardware"} and not model:
            model = value
        elif key == "vendor_id" and not vendor:
            vendor = value
        elif key == "cpu implementer" and not implementer:
            implementer = value
        elif key in {"flags", "features"} and not flags:
            flags = set(value.split())
        elif key == "physical id":
            sockets.add(value)
    vendor_name = {"GenuineIntel": "Intel Corporation", "AuthenticAMD": "Advanced Micro Devices, Inc.",
                   "HygonGenuine": "Hygon", "CentaurHauls": "Centaur/Zhaoxin"}.get(vendor or "", vendor)
    if not vendor_name and implementer:
        vendor_name = {"0x41": "Arm Limited", "0x48": "HiSilicon (Huawei)", "0xc0": "Ampere Computing",
                       "0x51": "Qualcomm", "0x61": "Apple"}.get(implementer.lower(), f"Arm implementer {implementer}")
    crypto = sorted({label for flag, label in CPU_CRYPTO_FLAGS.items() if flag in flags})
    return {
        "model": clean(model),
        "vendor": vendor_name,
        "logical_cpus": logical or os.cpu_count(),
        "sockets": len(sockets) or None,
        "crypto_extensions": crypto,
        "hypervisor": "hypervisor" in flags,
    }


def _meminfo_mb(ctx: Context) -> int | None:
    text = ctx.view.proc_text("meminfo", limit=65536) or ""
    match = re.search(r"^MemTotal:\s+(\d+)\s+kB", text, re.M)
    return int(match.group(1)) // 1024 if match else None


def _disks(ctx: Context) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    disks: list[dict[str, Any]] = []
    encrypted: list[dict[str, Any]] = []
    base = ctx.view.sys / "block"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return disks, encrypted
    for name in names:
        if name.startswith(("loop", "ram", "zram", "sr", "fd", "nbd")):
            continue
        def rd(rel: str) -> str | None:
            return clean(ctx.view.sys_text(f"block/{name}/{rel}"))
        if name.startswith("dm-"):
            uuid = rd("dm/uuid") or ""
            if uuid.startswith("CRYPT-"):
                kind = uuid.split("-")[1] if uuid.count("-") >= 1 else "CRYPT"
                try:
                    slaves = sorted(os.listdir(base / name / "slaves"))
                except OSError:
                    slaves = []
                encrypted.append({"device": name, "mapper_name": rd("dm/name"), "format": kind,
                                  "backing_devices": slaves})
            continue
        if name.startswith("md"):
            continue
        sectors = rd("size")
        size_gb = round(int(sectors) * 512 / 1e9, 1) if sectors and sectors.isdigit() else None
        if not size_gb:
            continue
        disks.append({
            "name": name,
            "model": rd("device/model"),
            "vendor": rd("device/vendor"),
            "serial": rd("device/serial") or rd("serial"),
            "wwid": rd("device/wwid") or rd("wwid"),
            "firmware": rd("device/firmware_rev") or rd("device/rev"),
            "size_gb": size_gb,
            "rotational": rd("queue/rotational") == "1",
            "transport": "nvme" if name.startswith("nvme") else ("virtio" if name.startswith("vd") else None),
        })
    return disks, encrypted


def _nics(ctx: Context) -> tuple[list[dict[str, Any]], int]:
    nics: list[dict[str, Any]] = []
    virtual = 0
    base = ctx.view.sys / "class" / "net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return nics, 0
    for name in names:
        if name == "lo":
            continue
        if not (base / name / "device").exists():
            virtual += 1
            continue
        def rd(rel: str) -> str | None:
            return clean(ctx.view.sys_text(f"class/net/{name}/{rel}"))
        driver = None
        try:
            driver = os.path.basename(os.readlink(base / name / "device" / "driver"))
        except OSError:
            pass
        speed = rd("speed")
        nics.append({"name": name, "mac": rd("address"), "state": rd("operstate"), "driver": driver,
                     "speed_mbps": int(speed) if speed and speed.lstrip("-").isdigit() and int(speed) > 0 else None,
                     "mtu": rd("mtu")})
    return nics, virtual


def _pci(ctx: Context) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    base = ctx.view.sys / "bus" / "pci" / "devices"
    try:
        slots = sorted(os.listdir(base))
    except OSError:
        return out
    for slot in slots:
        def rd(rel: str) -> str | None:
            return clean(ctx.view.sys_text(f"bus/pci/devices/{slot}/{rel}"))
        klass = (rd("class") or "").lower().replace("0x", "")
        label = None
        for prefix, name in PCI_CLASSES.items():
            if klass.startswith(prefix):
                label = name
                break
        if not label:
            continue
        vendor_id, device_id = (rd("vendor") or "").lower(), (rd("device") or "").lower()
        driver = None
        try:
            driver = os.path.basename(os.readlink(base / slot / "driver"))
        except OSError:
            pass
        crypto = klass.startswith("10") or (vendor_id == "0x8086" and device_id in INTEL_QAT_DEVICES)
        if vendor_id == "0x8086" and device_id in INTEL_QAT_DEVICES:
            label = "Intel QuickAssist (QAT) crypto accelerator"
        out.append({"slot": slot, "class": klass, "class_label": label, "vendor_id": vendor_id,
                    "device_id": device_id, "vendor": PCI_VENDORS.get(vendor_id, f"PCI vendor {vendor_id}"),
                    "driver": driver, "crypto_device": crypto})
        if len(out) >= 64:
            break
    return out


def _tpm(ctx: Context) -> dict[str, Any] | None:
    base = ctx.view.sys / "class" / "tpm"
    try:
        devices = sorted(d for d in os.listdir(base) if d.startswith("tpm"))
    except OSError:
        return None
    if not devices:
        return None
    name = devices[0]
    major = clean(ctx.view.sys_text(f"class/tpm/{name}/tpm_version_major"))
    caps = ctx.view.sys_text(f"class/tpm/{name}/device/caps") or ""
    if not major:
        match = re.search(r"TCG version:\s*([\d.]+)", caps)
        major = match.group(1) if match else None
    manufacturer = None
    match = re.search(r"Manufacturer:\s*(\S+)", caps)
    if match:
        manufacturer = match.group(1)
    hid = clean(ctx.view.sys_text(f"class/tpm/{name}/device/firmware_node/hid"))
    return {"device": name, "version": "2.0" if major == "2" else (major or "unknown"),
            "manufacturer": manufacturer, "acpi_hid": hid}


def _dimms(ctx: Context) -> tuple[list[dict[str, Any]], str | None]:
    result = run_allowed(["dmidecode", "-t", "memory"], timeout=10)
    if not result.ok:
        reason = result.stderr.strip().splitlines()[0] if result.stderr.strip() else f"exit {result.returncode}"
        return [], reason
    modules: list[dict[str, Any]] = []
    block: dict[str, str] | None = None
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if line.strip() == "Memory Device":
            if block:
                modules.append(block)
            block = {}
            continue
        if block is not None and ":" in line and line.startswith("\t") and not line.startswith("\t\t"):
            key, _, value = line.strip().partition(":")
            block[key.strip()] = value.strip()
    if block:
        modules.append(block)
    out = []
    for m in modules:
        size = m.get("Size", "")
        if not size or "No Module" in size or size.startswith("0"):
            continue
        out.append({"locator": clean(m.get("Locator")), "size": size, "type": clean(m.get("Type")),
                    "speed": clean(m.get("Speed")), "manufacturer": clean(m.get("Manufacturer")),
                    "serial": clean(m.get("Serial Number")), "part_number": clean(m.get("Part Number"))})
    return out, None


def _virtualization(dmi: dict[str, str], cpu: dict[str, Any], ctx: Context) -> str | None:
    probe = f"{dmi.get('sys_vendor', '')} {dmi.get('product_name', '')}".lower()
    for needle, label in VIRTUAL_PRODUCTS:
        if needle in probe:
            return label
    xen = ctx.view.sys_text("hypervisor/type")
    if xen:
        return xen
    if cpu.get("hypervisor"):
        return "hypervisor (type not identified)"
    return None


# --------------------------------------------------------------------------- #
# the plane
# --------------------------------------------------------------------------- #

def collect(ctx: Context) -> None:
    obs = ctx.obs
    view = ctx.view
    ctx.hostname = _hostname(ctx)
    domain = clean(ctx.config.get("domain"))
    ctx.fqdn = clean(ctx.config.get("fqdn")) or (
        ctx.hostname if "." in ctx.hostname or not domain else f"{ctx.hostname}.{domain}")
    ctx.primary_ip = _primary_ip(ctx)
    ctx.ip_addresses = sorted(set(_local_ipv4(ctx) + ([ctx.primary_ip] if ctx.primary_ip else [])))
    ctx.os_release = _os_release(ctx)
    dmi, dmi_unreadable = _dmi(ctx)
    cpu = _cpuinfo(ctx)
    machine_id = clean((view.read_text("/etc/machine-id", limit=128) or view.read_text(
        "/var/lib/dbus/machine-id", limit=128) or "").strip())
    ctx.machine_key = (dmi.get("product_uuid") or dmi.get("product_serial") or dmi.get("board_serial")
                       or machine_id or ctx.fqdn)
    fips = (view.proc_text("sys/crypto/fips_enabled", limit=8) or "").strip()
    kernel = (view.proc_text("sys/kernel/osrelease", limit=256) or "").strip() or None
    runtime = _container_runtime(ctx)
    virtualization = _virtualization(dmi, cpu, ctx)
    memory_mb = _meminfo_mb(ctx)
    tags = ctx.config.get("tags") or {}

    # -- the host ------------------------------------------------------------ #
    identity = {"hostname": ctx.fqdn}
    if ctx.primary_ip:
        identity["ip_address"] = ctx.primary_ip
    obs.asset(ctx.host_ref, "HOST", ctx.hostname, identity=identity, environment=ctx.environment,
              attributes={
                  "fqdn": ctx.fqdn,
                  "ip_addresses": ctx.ip_addresses,
                  "os": ctx.os_release.get("PRETTY_NAME"),
                  "os_id": ctx.os_release.get("ID"),
                  "os_version": ctx.os_release.get("VERSION_ID"),
                  "kernel": kernel,
                  "architecture": os.uname().machine,
                  "machine_id": machine_id,
                  "virtualization": virtualization,
                  "container_runtime": runtime,
                  "fips_mode": fips == "1" if fips else None,
                  "logical_cpus": cpu.get("logical_cpus"),
                  "memory_mb": memory_mb,
                  "agent": f"cryptava {__version__}",
                  "agent_name": ctx.config.get("name"),
                  "datacenter": tags.get("datacenter"),
                  "owner": tags.get("owner"),
              }, source="cryptava-host")
    ctx.host_evidence = obs.observe(ctx.host_ref, "RUNTIME_OBSERVED", {
        "hostname": ctx.fqdn, "os": ctx.os_release.get("PRETTY_NAME"), "kernel": kernel,
        "ip_addresses": ctx.ip_addresses, "virtualization": virtualization,
        "container_runtime": runtime, "source": "/etc/os-release, /proc, /sys",
    }, layer="PLATFORM", source="cryptava-host")
    if fips:
        obs.observe(ctx.host_ref, "RUNTIME_OBSERVED", {
            "fips_enabled": fips == "1", "source": "/proc/sys/crypto/fips_enabled",
            "role": "kernel-fips-mode",
        }, layer="PLATFORM", source="cryptava-host")

    # -- the platform (chassis / board) -------------------------------------- #
    reg = asset_register.get(ctx)
    hw = reg.hardware
    register_identity = reg.hardware_identified()
    vendor = dmi.get("sys_vendor") or dmi.get("board_vendor")
    model = dmi.get("product_name") or dmi.get("board_name")
    from_register = not dmi and register_identity
    if from_register:
        vendor, model = hw.get("manufacturer"), hw.get("model")
    system_name = " ".join(x for x in (vendor, model) if x) or (
        f"{virtualization} virtual machine" if virtualization else "Unidentified platform (no DMI)")
    serial = dmi.get("product_serial") or dmi.get("chassis_serial") or (hw.get("serial_number") if from_register else None)
    asset_tag = dmi.get("chassis_asset_tag") or hw.get("asset_tag")
    system_identity = {"serial_number": serial, "model": model} if serial else {
        "asset_tag": f"{ctx.machine_key}:system", "model": model or system_name}
    warranty = asset_register.date_state(hw.get("warranty_end"), active="IN_WARRANTY",
                                         lapsed="OUT_OF_WARRANTY") if hw.get("warranty_end") else None
    ctx.system_ref = obs.asset("hw:system", "HARDWARE", system_name, identity=system_identity, attributes={
        "component": "system", "vendor": vendor, "model": model, "family": dmi.get("product_family"),
        "version": dmi.get("product_version"), "serial_number": serial, "uuid": dmi.get("product_uuid"),
        "board": " ".join(x for x in (dmi.get("board_vendor"), dmi.get("board_name")) if x) or None,
        "chassis_type": CHASSIS_TYPES.get(dmi.get("chassis_type", ""), dmi.get("chassis_type")),
        "asset_tag": asset_tag, "virtualization": virtualization,
        "memory_mb": memory_mb,
        "identity_source": "firmware (DMI)" if dmi else ("asset register" if from_register else None),
        "platform": hw.get("platform"), "location": hw.get("location"), "rack": hw.get("rack"),
        "cluster": hw.get("cluster"), "warranty_end": hw.get("warranty_end"), "warranty_state": warranty,
        "end_of_life": hw.get("end_of_life"), "hardware_owner": hw.get("owner"),
    }, source="cryptava-dmi" if dmi or not from_register else "cryptava-asset-register")
    ctx.system_evidence = obs.observe(ctx.system_ref, "STATIC_OBSERVED", {
        "vendor": dmi.get("sys_vendor") or dmi.get("board_vendor"),
        "model": dmi.get("product_name") or dmi.get("board_name"),
        "serial_number": dmi.get("product_serial") or dmi.get("chassis_serial"),
        "virtualization": virtualization, "container_runtime": runtime,
        "memory_mb": memory_mb, "dmi_available": bool(dmi),
        "dmi_unreadable": dmi_unreadable or None,
        "source": "/sys/class/dmi/id" if dmi else "no DMI tables exposed by this platform",
    }, layer="PLATFORM", source="cryptava-dmi")
    system_evidence = [ctx.host_evidence, ctx.system_evidence]
    register_mismatch = None
    if hw:
        register_ev = obs.observe(ctx.system_ref, "IMPORTED", {
            **hw, "record": "hardware-asset", "warranty_state": warranty, "host": ctx.fqdn,
            "source": reg.label, "exported_at": reg.exported_at, "file": reg.path,
        }, layer="PLATFORM", source="cryptava-asset-register")
        system_evidence.append(register_ev)
        if from_register:
            ctx.system_evidence = register_ev
        firmware_serial = dmi.get("product_serial") or dmi.get("chassis_serial")
        if firmware_serial and hw.get("serial_number") and \
                firmware_serial.strip().lower() != str(hw["serial_number"]).strip().lower():
            register_mismatch = (f"asset register serial {hw['serial_number']} differs from firmware serial "
                                 f"{firmware_serial}")
            obs.observe(ctx.system_ref, "STATIC_OBSERVED", {
                "register_serial": hw["serial_number"], "firmware_serial": firmware_serial,
                "role": "asset-register-mismatch", "host": ctx.fqdn,
                "note": "the CMDB record and the firmware disagree; the firmware value is used",
            }, layer="PLATFORM", source="cryptava-dmi")
    obs.relate(ctx.host_ref, "hosted_on", ctx.system_ref, basis="RUNTIME_OBSERVATION",
               evidence=system_evidence)
    if vendor:
        note = "DMI system vendor" if dmi else "asset register (CMDB)"
        ctx.vendor_links.append((ctx.system_ref, vendor, model or "platform", dmi.get("product_version"), note))

    components = 0
    # -- firmware ------------------------------------------------------------ #
    if dmi.get("bios_version"):
        fw = obs.asset(f"fw:bios:{slug(dmi.get('bios_vendor', 'bios'))}:{slug(dmi['bios_version'])}",
                       "FIRMWARE", f"{dmi.get('bios_vendor', 'BIOS')} {dmi['bios_version']}",
                       identity={"vendor": dmi.get("bios_vendor"), "version": dmi["bios_version"],
                                 "component": "system-bios"},
                       attributes={"release_date": dmi.get("bios_date"), "release": dmi.get("bios_release"),
                                   "component": "system-bios"}, source="cryptava-dmi")
        ev = obs.observe(fw, "STATIC_OBSERVED", {"version": dmi["bios_version"], "vendor": dmi.get("bios_vendor"),
                                                 "release_date": dmi.get("bios_date"), "host": ctx.fqdn,
                                                 "source": "/sys/class/dmi/id/bios_*"},
                         layer="PLATFORM", source="cryptava-dmi")
        obs.relate(fw, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        if dmi.get("bios_vendor"):
            ctx.vendor_links.append((fw, dmi["bios_vendor"], "system firmware", dmi["bios_version"], "DMI BIOS vendor"))
        components += 1

    # -- CPU ----------------------------------------------------------------- #
    if cpu.get("model") or cpu.get("logical_cpus"):
        cpu_ref = obs.asset("hw:cpu", "HARDWARE", cpu.get("model") or "CPU",
                            identity={"asset_tag": f"{ctx.machine_key}:cpu", "model": cpu.get("model")},
                            attributes={"component": "cpu", "vendor": cpu.get("vendor"),
                                        "logical_cpus": cpu.get("logical_cpus"), "sockets": cpu.get("sockets"),
                                        "crypto_extensions": cpu.get("crypto_extensions")},
                            source="cryptava-cpuinfo")
        ev = obs.observe(cpu_ref, "STATIC_OBSERVED", {"model": cpu.get("model"), "vendor": cpu.get("vendor"),
                                                      "logical_cpus": cpu.get("logical_cpus"), "host": ctx.fqdn,
                                                      "source": "/proc/cpuinfo"},
                         layer="PLATFORM", source="cryptava-cpuinfo")
        obs.relate(cpu_ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        if cpu.get("crypto_extensions"):
            # capability, not use: a CPU that *can* do AES-NI says nothing about who uses it
            obs.observe(cpu_ref, "STATIC_OBSERVED", {
                "supported_algorithms": cpu["crypto_extensions"], "host": ctx.fqdn,
                "basis": "CPU feature flags", "source": "/proc/cpuinfo flags",
            }, layer="PLATFORM", source="cryptava-cpuinfo")
        if cpu.get("vendor"):
            ctx.vendor_links.append((cpu_ref, cpu["vendor"], "processor", cpu.get("model"), "CPU vendor_id"))
        components += 1

    # -- memory -------------------------------------------------------------- #
    dimms, dimm_reason = ([], None)
    if ctx.config.get("dmidecode", True):
        dimms, dimm_reason = _dimms(ctx)
    for index, dimm in enumerate(dimms):
        ref = f"hw:dimm:{index}"
        ident = {"serial_number": dimm["serial"]} if dimm.get("serial") else {"asset_tag": f"{ctx.machine_key}:dimm:{dimm.get('locator') or index}"}
        ident["model"] = dimm.get("part_number") or dimm.get("type")
        obs.asset(ref, "HARDWARE", f"{dimm.get('manufacturer') or 'Memory'} {dimm.get('size')} {dimm.get('type') or ''}".strip(),
                  identity=ident, attributes={"component": "memory-module", **dimm}, source="cryptava-dmidecode")
        ev = obs.observe(ref, "STATIC_OBSERVED", {**dimm, "host": ctx.fqdn, "source": "dmidecode -t memory"},
                         layer="PLATFORM", source="cryptava-dmidecode")
        obs.relate(ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        components += 1
    if not dimms and memory_mb:
        ref = obs.asset("hw:memory", "HARDWARE", f"System memory {round(memory_mb / 1024, 1)} GiB",
                        identity={"asset_tag": f"{ctx.machine_key}:memory", "model": "system memory"},
                        attributes={"component": "memory", "total_mb": memory_mb}, source="cryptava-meminfo")
        ev = obs.observe(ref, "STATIC_OBSERVED", {"total_mb": memory_mb, "host": ctx.fqdn, "source": "/proc/meminfo",
                                                  "dimm_detail": dimm_reason or "not requested"},
                         layer="PLATFORM", source="cryptava-meminfo")
        obs.relate(ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        components += 1

    # -- disks + disk firmware + encrypted volumes --------------------------- #
    disks, encrypted = _disks(ctx)
    for disk in disks:
        ref = f"hw:disk:{disk['name']}"
        ident = {"serial_number": disk["serial"] or disk["wwid"]} if (disk["serial"] or disk["wwid"]) else {
            "asset_tag": f"{ctx.machine_key}:disk:{disk['name']}"}
        ident["model"] = disk["model"]
        label = " ".join(x for x in (disk.get("vendor"), disk.get("model")) if x) or f"Disk {disk['name']}"
        obs.asset(ref, "HARDWARE", f"{label} ({disk['size_gb']} GB)", identity=ident,
                  attributes={"component": "disk", **disk}, source="cryptava-sysfs")
        ev = obs.observe(ref, "STATIC_OBSERVED", {**{k: v for k, v in disk.items() if k != "wwid"}, "host": ctx.fqdn,
                                                  "source": f"/sys/block/{disk['name']}"},
                         layer="PLATFORM", source="cryptava-sysfs")
        obs.relate(ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        components += 1
        if disk.get("firmware") and disk.get("model"):
            fw = obs.asset(f"fw:disk:{slug(disk['model'])}:{slug(disk['firmware'])}", "FIRMWARE",
                           f"{disk['model']} firmware {disk['firmware']}",
                           identity={"vendor": disk.get("vendor") or disk["model"], "version": disk["firmware"],
                                     "component": f"disk:{disk['model']}"},
                           attributes={"component": "disk-firmware"}, source="cryptava-sysfs")
            fev = obs.observe(fw, "STATIC_OBSERVED", {"version": disk["firmware"], "disk": disk["name"],
                                                      "host": ctx.fqdn, "source": f"/sys/block/{disk['name']}/device"},
                              layer="PLATFORM", source="cryptava-sysfs")
            obs.relate(fw, "part_of", ref, basis="RUNTIME_OBSERVATION", evidence=[fev])
    for volume in encrypted:
        obs.observe(ctx.host_ref, "STATIC_OBSERVED", {
            "algorithm": f"dm-crypt/{volume['format']}", "role": "volume-encryption",
            "volume": volume.get("mapper_name") or volume["device"], "backing_devices": volume["backing_devices"],
            "usage_state": "CONFIGURED", "source": f"/sys/block/{volume['device']}/dm/uuid",
            "note": "cipher detail needs root (dmsetup table); format is from the dm uuid",
        }, layer="STORAGE", source="cryptava-sysfs")

    # -- NICs ---------------------------------------------------------------- #
    nics, virtual_nics = _nics(ctx)
    for nic in nics:
        ref = f"hw:nic:{nic['name']}"
        ident = {"serial_number": f"mac:{nic['mac']}"} if nic.get("mac") else {"asset_tag": f"{ctx.machine_key}:nic:{nic['name']}"}
        ident["model"] = nic.get("driver")
        obs.asset(ref, "HARDWARE", f"NIC {nic['name']} ({nic.get('driver') or 'unknown driver'})", identity=ident,
                  attributes={"component": "nic", **nic}, source="cryptava-sysfs")
        ev = obs.observe(ref, "STATIC_OBSERVED", {**nic, "host": ctx.fqdn, "source": f"/sys/class/net/{nic['name']}"},
                         layer="PLATFORM", source="cryptava-sysfs")
        obs.relate(ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        components += 1

    # -- PCI (storage/network/GPU/crypto accelerators) ----------------------- #
    pci_devices = _pci(ctx)
    pci_count = len(pci_devices)
    for device in pci_devices:
        ref = f"hw:pci:{device['slot']}"
        name = f"{device['vendor']} {device['class_label']} [{device['device_id']}]"
        obs.asset(ref, "HARDWARE", name,
                  identity={"asset_tag": f"{ctx.machine_key}:pci:{device['slot']}",
                            "model": f"{device['vendor_id']}:{device['device_id']}"},
                  attributes={"component": "pci-device", **device}, source="cryptava-sysfs")
        ev = obs.observe(ref, "STATIC_OBSERVED", {**device, "host": ctx.fqdn,
                                                  "source": f"/sys/bus/pci/devices/{device['slot']}"},
                         layer="PLATFORM", source="cryptava-sysfs")
        obs.relate(ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        if device["crypto_device"]:
            obs.observe(ref, "STATIC_OBSERVED", {"supported_algorithms": ["hardware crypto offload"],
                                                 "device": device["class_label"], "host": ctx.fqdn,
                                                 "source": "PCI class code / device id"},
                        layer="PLATFORM", source="cryptava-sysfs")
        if not device["vendor"].startswith("PCI vendor"):
            ctx.vendor_links.append((ref, device["vendor"], device["class_label"], None, "PCI vendor id"))
        components += 1

    # -- TPM ----------------------------------------------------------------- #
    tpm = _tpm(ctx)
    if tpm:
        ref = obs.asset("hw:tpm", "HARDWARE", f"TPM {tpm['version']}",
                        identity={"asset_tag": f"{ctx.machine_key}:tpm", "model": f"TPM {tpm['version']}"},
                        attributes={"component": "tpm", **tpm}, source="cryptava-sysfs")
        ev = obs.observe(ref, "STATIC_OBSERVED", {**tpm, "host": ctx.fqdn, "source": f"/sys/class/tpm/{tpm['device']}"},
                         layer="PLATFORM", source="cryptava-sysfs")
        obs.relate(ref, "part_of", ctx.system_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
        if tpm["version"] == "2.0":
            obs.observe(ref, "STATIC_OBSERVED", {
                "supported_algorithms": ["RSA-2048", "ECDSA P-256", "SHA-256", "SHA-1", "HMAC", "AES-128-CFB"],
                "basis": "TCG PC Client TPM 2.0 mandatory algorithm set", "host": ctx.fqdn,
            }, layer="PLATFORM", source="cryptava-sysfs")
        components += 1

    # -- status: identity + nothing refused --------------------------------- #
    dimm_wanted = bool(ctx.config.get("dmidecode", True))
    gaps: list[str] = []
    notes: list[str] = []
    if dmi:
        notes.append("platform identity from firmware (DMI)")
    elif register_identity:
        notes.append(f"platform identity from the asset register ({reg.label}); this platform exposes no "
                     "firmware tables" + (f" — {runtime} container" if runtime else ""))
    else:
        where = reg.path or asset_register.DEFAULT_RECORD_PATH
        gaps.append("no DMI tables and no asset-register hardware record (platform identity unknown) — "
                    f"add a 'hardware' record to {where}")
    if dmi and dmi_unreadable and not (register_identity and hw.get("serial_number")):
        gaps.append(f"{len(dmi_unreadable)} DMI fields need root ({', '.join(dmi_unreadable[:4])})")
    if register_mismatch:
        notes.append(register_mismatch)
    if dimm_wanted and dimm_reason:
        if dmi and not runtime:
            gaps.append(f"DIMM detail unavailable: {dimm_reason[:80]}")
        else:
            notes.append("memory size from /proc/meminfo (DIMM layout is not visible "
                         + ("inside a container" if runtime else "without firmware tables") + ")")
    status = "PARTIAL" if gaps else "COMPLETE"

    sources = [
        source("/sys/class/dmi/id", "platform vendor, model, serial, UUID, BIOS",
               "READ" if dmi and not dmi_unreadable else ("DENIED" if dmi_unreadable else "ABSENT"),
               len(dmi) or None, f"{len(dmi_unreadable)} root-only fields unreadable" if dmi_unreadable else None),
        source(reg.path or asset_register.DEFAULT_RECORD_PATH, "hardware record: model, serial, asset tag, rack, warranty",
               "READ" if hw else ("EMPTY" if reg.state == "READ" else reg.state),
               len(hw) or None, reg.note or (reg.label if hw else "supply it from the CMDB")),
        source("/proc/cpuinfo", "CPU model, vendor, cores, crypto extensions", "READ" if cpu.get("model") or
               cpu.get("logical_cpus") else "EMPTY", cpu.get("logical_cpus")),
        source("/proc/meminfo", "installed memory", "READ" if memory_mb else "EMPTY", None,
               f"{round(memory_mb / 1024, 1)} GiB" if memory_mb else None),
        source("dmidecode -t memory", "memory modules (DIMMs)",
               "DISABLED" if not dimm_wanted else ("READ" if dimms else "UNAVAILABLE"),
               len(dimms) if dimms else None, dimm_reason[:120] if dimm_reason else None),
        source("/sys/block", "disks, disk firmware, dm-crypt volumes", "READ" if disks else "EMPTY",
               len(disks), f"{len(encrypted)} encrypted volumes" if encrypted else None),
        source("/sys/class/net", "network interfaces", "READ" if nics else "EMPTY", len(nics),
               f"{virtual_nics} virtual interfaces skipped" if virtual_nics else None),
        source("/sys/bus/pci/devices", "storage / network / GPU / crypto PCI devices",
               "READ" if pci_count else ("EMPTY" if (view.sys / "bus/pci/devices").is_dir() else "ABSENT"), pci_count),
        source("/sys/class/tpm", "TPM version and manufacturer", "READ" if tpm else "ABSENT", 1 if tpm else 0),
    ]
    reason = f"{components} hardware components read"
    if gaps:
        reason += "; " + "; ".join(gaps)
    if notes:
        reason += "; " + "; ".join(notes)
    obs.plane("HBOM · hardware", status, reason, expected=1, collected=1,
              details={"virtual_nics": virtual_nics, "encrypted_volumes": len(encrypted)}, sources=sources)
    obs.cover(f"{ctx.hostname} · hardware components", components or 1, components)

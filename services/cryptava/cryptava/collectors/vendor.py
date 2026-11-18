"""VBOM: who supplies what runs here — derived from what the other planes observed.

Every vendor here is traceable: the hardware manufacturer from DMI, the CPU vendor
from ``/proc/cpuinfo``, the operating-system publisher from ``/etc/os-release``, the
package vendor from the rpm header (or the distribution that published a ``.deb`` /
``.apk``), the crypto-library project from the library family, the certificate
authority from the certificate issuer. Each vendor gets a ``VENDOR_DECLARED`` record
(product, version, support lifecycle where it is public, PQC readiness where the
release line is known) — the platform keeps these as *declarations*, never as proof
of use.

Contracts, support entitlements and account managers are not on the host; they come
from the bank's CMDB / procurement import and are reported as not collected.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from cryptava.collectors import Context
from cryptava.util import slug

VENDOR_ALIASES = {
    "genuineintel": "Intel", "intel corporation": "Intel", "intel corp.": "Intel", "intel": "Intel",
    "authenticamd": "AMD", "advanced micro devices, inc.": "AMD", "advanced micro devices": "AMD",
    "dell inc.": "Dell Technologies", "dell": "Dell Technologies", "hpe": "Hewlett Packard Enterprise",
    "hp": "HP", "hewlett-packard": "Hewlett Packard Enterprise", "lenovo": "Lenovo",
    "supermicro": "Supermicro", "super micro computer": "Supermicro", "cisco systems inc": "Cisco",
    "vmware, inc.": "VMware", "vmware": "VMware", "qemu": "QEMU", "innotek gmbh": "Oracle (VirtualBox)",
    "microsoft corporation": "Microsoft", "amazon ec2": "Amazon Web Services", "google": "Google Cloud",
    "red hat, inc.": "Red Hat", "red hat": "Red Hat", "canonical": "Canonical", "suse llc": "SUSE",
    "openssl": "OpenSSL Software Foundation", "gnutls": "GnuTLS project", "nss": "Mozilla (NSS)",
    "libgcrypt": "GnuPG project", "libsodium": "libsodium project", "mbed tls": "Trusted Firmware (Mbed TLS)",
    "wolfssl": "wolfSSL Inc.", "boringssl": "Google (BoringSSL)", "nettle": "GNU Nettle project",
    "liboqs": "Open Quantum Safe", "java runtime (jca/jce)": "Java runtime vendor",
    "mellanox technologies": "NVIDIA (Mellanox)", "broadcom inc. and subsidiaries": "Broadcom",
    "broadcom": "Broadcom", "emulex corporation": "Broadcom (Emulex)", "qlogic corp.": "Marvell (QLogic)",
    "samsung electronics co ltd": "Samsung", "seagate": "Seagate", "toshiba": "Toshiba", "kioxia": "Kioxia",
    "western digital": "Western Digital", "micron": "Micron", "red hat, inc": "Red Hat",
    "infineon": "Infineon", "ifx": "Infineon", "stm": "STMicroelectronics", "ntc": "Nuvoton", "nuvoton": "Nuvoton",
}

OS_VENDORS = {
    "debian": "Debian Project", "ubuntu": "Canonical", "rhel": "Red Hat", "centos": "CentOS Project",
    "rocky": "Rocky Enterprise Software Foundation", "almalinux": "AlmaLinux OS Foundation",
    "ol": "Oracle", "sles": "SUSE", "sled": "SUSE", "opensuse-leap": "SUSE", "alpine": "Alpine Linux",
    "amzn": "Amazon Web Services", "fedora": "Fedora Project",
}

#: published end of standard support (vendor lifecycle pages); unknown releases stay unknown
OS_SUPPORT_END = {
    ("debian", "10"): "2024-06-30", ("debian", "11"): "2026-08-31", ("debian", "12"): "2028-06-30",
    ("debian", "13"): "2030-06-30",
    ("ubuntu", "18.04"): "2023-05-31", ("ubuntu", "20.04"): "2025-05-31", ("ubuntu", "22.04"): "2027-06-30",
    ("ubuntu", "24.04"): "2029-06-30",
    ("rhel", "7"): "2024-06-30", ("rhel", "8"): "2029-05-31", ("rhel", "9"): "2032-05-31",
    ("rocky", "8"): "2029-05-31", ("rocky", "9"): "2032-05-31",
    ("almalinux", "8"): "2029-05-31", ("almalinux", "9"): "2032-05-31",
    ("centos", "7"): "2024-06-30", ("sles", "12"): "2024-10-31", ("sles", "15"): "2031-07-31",
}

#: package families that matter for crypto posture — linked to their supplier one by one
CRYPTO_PACKAGE = re.compile(
    r"^(lib)?(ssl|openssl|crypto|gnutls|nss|gcrypt|sodium|mbedtls|wolfssl|nettle|oqs|openssh|ssh|"
    r"krb5|gpg|gnupg|ca-certificates|p11|softhsm|tpm2|opensc|strongswan|libreswan|java|openjdk|"
    r"nginx|apache2|httpd|haproxy|postgresql|mysql|mariadb|bouncycastle|bcprov|cryptography|pyopenssl)",
    re.I)


def canonical_vendor(raw: str | None) -> str | None:
    if not raw:
        return None
    text = re.sub(r"<[^>]*>", "", str(raw)).strip().strip(",")
    if not text:
        return None
    lowered = text.lower()
    if lowered in VENDOR_ALIASES:
        return VENDOR_ALIASES[lowered]
    for key, value in VENDOR_ALIASES.items():
        if len(key) > 3 and lowered.startswith(key):
            return value
    return text[:120]


def _support(os_id: str, version: str | None) -> dict[str, Any]:
    if not version:
        return {}
    key = (os_id, version.split(".")[0] if os_id not in {"ubuntu"} else version)
    end = OS_SUPPORT_END.get(key)
    if not end:
        return {}
    state = "SUPPORTED" if date.fromisoformat(end) >= date.today() else "END_OF_SUPPORT"
    return {"support_lifecycle": state, "support_end": end}


class _Vendors:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.declared: set[tuple[str, str, str | None]] = set()

    def link(self, subject: str, vendor_raw: str | None, product: str, version: str | None, note: str,
             *, basis: str, extra: dict[str, Any] | None = None) -> str | None:
        ctx, obs = self.ctx, self.ctx.obs
        vendor = canonical_vendor(vendor_raw)
        if not vendor or not obs.has(subject):
            return None
        key = (vendor, product)
        ref = ctx.vendors.get(key)
        if ref is None:
            ref = obs.asset(f"vendor:{slug(vendor, limit=50)}:{slug(product, limit=50)}", "VENDOR",
                            f"{vendor} · {product}", identity={"name": vendor, "product": product},
                            attributes={"vendor": vendor, "product": product}, source="cryptava-vbom")
            ctx.vendors[key] = ref
        facts = {"product": product, "version": version, "vendor": vendor, "declared_from": note,
                 "host": ctx.fqdn, **(extra or {})}
        ev = obs.observe(ref, "VENDOR_DECLARED", facts, layer="PLATFORM", source="cryptava-vbom")
        obs.relate(subject, "provided_by", ref, basis=basis, evidence=[ev])
        return ref


def collect(ctx: Context) -> None:
    vendors = _Vendors(ctx)
    obs = ctx.obs
    os_id = (ctx.os_release.get("ID") or "").lower()
    os_name = ctx.os_release.get("NAME") or os_id or "Linux"
    os_version = ctx.os_release.get("VERSION_ID")
    distro_vendor = OS_VENDORS.get(os_id) or (ctx.os_release.get("NAME") if os_id else None)

    # 1. operating system publisher
    if distro_vendor:
        vendors.link(ctx.host_ref, distro_vendor, f"{os_name} (operating system)", os_version,
                     "/etc/os-release", basis="RUNTIME_OBSERVATION", extra=_support(os_id, os_version))

    # 2. links queued by the other planes: hardware, firmware, CPU, PCI, libraries, CAs
    for subject, vendor_raw, product, version, note in ctx.vendor_links:
        extra: dict[str, Any] = {}
        if subject.startswith("lib:"):
            attrs = obs.assets[subject]["attributes"]
            family = attrs.get("family", product)
            extra["pqc_ready"] = _library_pqc(family, attrs.get("version"))
            basis = "DEPLOYMENT_CONFIG"
        elif subject.startswith(("ca:", "cert:")):
            basis = "CONFIGURATION"
        else:
            basis = "RUNTIME_OBSERVATION"
        vendors.link(subject, vendor_raw, product, version, note, basis=basis, extra=extra)

    # 3. packages: rpm carries its own Vendor tag; .deb/.apk come from the distribution.
    linked_packages = 0
    for name, package in sorted(ctx.packages.items()):
        if not CRYPTO_PACKAGE.match(name):
            continue
        supplier = package.get("vendor")
        if not supplier and package["ecosystem"] in {"deb", "apk"}:
            supplier = distro_vendor
        if not supplier and package["ecosystem"] == "pypi":
            supplier = "Python Package Index (community)"
        if not supplier and package["ecosystem"] == "maven":
            supplier = "Maven Central (community)"
        if supplier and vendors.link(package["ref"], supplier, name, package.get("version"),
                                     f"{package['ecosystem']} package metadata", basis="DEPLOYMENT_CONFIG"):
            linked_packages += 1

    total = len(ctx.vendors)
    if total == 0:
        obs.plane("VBOM · vendors", "FAILED", "no vendor could be attributed from hardware, OS or packages",
                  expected=1, collected=0)
        return
    obs.plane("VBOM · vendors", "PARTIAL",
              f"{total} vendor products ({linked_packages} crypto-relevant packages attributed); contracts and "
              "support entitlements are not on the host — import them from the CMDB",
              expected=2, collected=1)


def _library_pqc(family: str, version: str | None) -> bool | None:
    if family == "liboqs":
        return True
    if family == "OpenSSL" and version:
        nums = [int(x) for x in re.findall(r"\d+", version)[:2]] + [0, 0]
        return (nums[0], nums[1]) >= (3, 5)
    if family in {"BoringSSL", "wolfSSL"}:
        return None  # release-dependent; not derivable from the soname
    return None

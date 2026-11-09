"""Linux Kernel Crypto API inventory (/proc/crypto parser) — the
central part of the Linux collector (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md §2.2).

Entries are separated into blank-line blocks of `key : value` lines.
Parsing is bounded and fail-safe: malformed fields are dropped with
their reason, never guessed. The output is an inventory of REGISTERED
IMPLEMENTATIONS — never proof of runtime use (§2.2), and the generic
algorithm name is kept distinct from the implementation driver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MAX_ENTRIES = 4096
MAX_LINE = 4096

_INT_FIELDS = ("priority", "blocksize", "digestsize", "min_keysize",
               "max_keysize", "ivsize", "seedsize", "statesize")
_TEXT_FIELDS = ("name", "driver", "module", "type", "selftest",
                "internal", "async", "geniv")
_ALL_FIELDS = set(_INT_FIELDS) | set(_TEXT_FIELDS)


@dataclass
class CryptoApiEntry:
    name: str = ""
    driver: str = ""
    type: str = ""
    module: str = ""
    priority: Optional[int] = None
    blocksize: Optional[int] = None
    digestsize: Optional[int] = None
    min_keysize: Optional[int] = None
    max_keysize: Optional[int] = None
    selftest: str = ""
    internal: str = ""
    async_: str = ""
    raw_fields: Dict[str, str] = field(default_factory=dict)
    parse_notes: List[str] = field(default_factory=list)

    @property
    def hardware_accelerated(self) -> Optional[bool]:
        """Heuristic indicator, stated as an indicator: a driver that is
        not the generic fallback and names an arch/hw feature. None when
        determinable neither way — never guessed."""
        if not self.driver:
            return None
        generic = ("generic", "software", "cipher_null", "digest_null",
                   "compress_null")
        if any(tag in self.driver for tag in generic):
            return False
        hw_tags = ("aesni", "avx", "sha1-", "sha256-", "sha512-", "-ni",
                   "intel", "arm64",
                   "neon", "ce", "ccp", "qat", "nitrox", "caam", "stm32",
                   "hifn", "geode", "padlock", "via-", "mv_cesa", "sun8i",
                   "rockchip", "bcm", "octeontx", "crypto_", "virtio",
                   "padlock", "atmel", "n2", "stm32")
        return any(tag in self.driver for tag in hw_tags)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.name,
            "driver": self.driver,
            "type": self.type,
            "module": self.module or "(built-in or unknown)",
            "priority": self.priority,
            "blocksize": self.blocksize,
            "digestsize": self.digestsize,
            "key_size_range": ([self.min_keysize, self.max_keysize]
                               if self.min_keysize or self.max_keysize
                               else None),
            "selftest": self.selftest or "unreported",
            "hardware_accelerated": self.hardware_accelerated,
            "parse_notes": self.parse_notes,
            "runtime_usage_confirmed": False,
            "note": "registered kernel crypto implementation — "
                    "inventory, not proof of runtime use (§2.2); the "
                    "generic algorithm name and the implementation "
                    "driver are distinct (§2.2)",
        }


def parse_crypto_api(text: str) -> Tuple[List[CryptoApiEntry], List[str]]:
    """Parse /proc/crypto content. Returns (entries, parse_notes)."""
    entries: List[CryptoApiEntry] = []
    notes: List[str] = []
    current: Dict[str, str] = {}

    def flush() -> None:
        if not current:
            return
        if len(entries) >= MAX_ENTRIES:
            return
        entry = CryptoApiEntry(raw_fields=dict(current))
        entry.name = current.get("name", "")
        entry.driver = current.get("driver", "")
        entry.type = current.get("type", "")
        entry.module = current.get("module", "")
        entry.selftest = current.get("selftest", "")
        entry.internal = current.get("internal", "")
        entry.async_ = current.get("async", "")
        for key in _INT_FIELDS:
            if key in current:
                try:
                    setattr(entry, key if key != "async" else "async_",
                            int(current[key]))
                except ValueError:
                    entry.parse_notes.append(
                        f"{key}={current[key]!r} is not an integer — "
                        "left unknown, never guessed")
        for key in current:
            if key not in _ALL_FIELDS:
                entry.parse_notes.append(
                    f"unrecognized field {key!r} preserved in raw_fields")
        if not entry.name and not entry.driver:
            entry.parse_notes.append(
                "entry has neither name nor driver — recorded as "
                "unidentified, never guessed")
        entries.append(entry)
        current.clear()

    for raw_line in text.splitlines()[:MAX_ENTRIES * 16]:
        line = raw_line[:MAX_LINE]
        if not line.strip():
            flush()
            continue
        if ":" not in line:
            notes.append(f"line without a key/value separator skipped: "
                         f"{line[:60]!r}")
            continue
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip()
    flush()
    if len(entries) >= MAX_ENTRIES:
        notes.append(f"entry count reached the bounded limit "
                     f"{MAX_ENTRIES} — the remainder is unknown, never "
                     "guessed")
    return entries, notes

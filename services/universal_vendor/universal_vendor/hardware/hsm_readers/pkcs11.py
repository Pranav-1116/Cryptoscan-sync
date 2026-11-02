"""PKCS#11 -> HSM facts (phase H4): partitions and mechanisms, no key material.

PKCS#11 is the vendor-neutral door into an HSM. Every appliance in a bank's
estate — Thales Luna, Entrust nShield, Utimaco, SoftHSM, a cloud HSM in PKCS#11
mode — exposes ``CK_TOKEN_INFO`` and ``C_GetMechanismList``, and between them
those two answer the questions the review asked:

* **which partition is this** — token label, serial, model, manufacturer;
* **what firmware is on it** — ``firmwareVersion`` and ``hardwareVersion``;
* **what crypto it can do** — the mechanism list, including the post-quantum
  mechanisms an appliance advertises (``CKM_ML_KEM``, ``CKM_ML_DSA``,
  ``CKM_SLH_DSA``, ``CKM_FN_DSA``);
* **how it is configured to be used** — login required, write protected, RNG.

What it does *not* read: no object is fetched, no key value is read, and there is
no ``C_GetAttributeValue`` call in this module at all.

Two boundaries are structural:

* **The PIN never reaches argv.** ``pkcs11-tool --pin <value>`` would put the
  partition's PIN in ``ps`` output for every other user on the host. The reader
  passes a *reference* and sets ``PKCS11_PIN`` in the child's environment, which
  is the only channel used; an argv carrying ``--pin`` is refused
  (:class:`PinOnCommandLineRefused`).
* **Only ``pkcs11-tool`` runs**, with a module path that must be an absolute
  path to a regular file, and arguments that must be plain argv elements.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 - fixed argv, shell=False, allowlisted binary
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA = "cryptoscan.hsm-pkcs11/1"

#: The only program this reader may execute.
ALLOWED_BINARIES = frozenset({"pkcs11-tool"})

#: Environment variable the PIN is read from. The name, never the value,
#: appears anywhere in a fact record.
PIN_ENV = "PKCS11_PIN"

_ARGUMENT = re.compile(r"^[A-Za-z0-9_@%+=:,./\-]{1,512}$")
_SLOT_LINE = re.compile(r"^Slot\s+(\d+)\s+\(0x[0-9a-fA-F]+\)\s*:\s*(.*)$")
_FIELD_LINE = re.compile(r"^\s+([A-Za-z][A-Za-z0-9 _\-]*?)\s*:\s*(.*)$")
_MECHANISM_LINE = re.compile(r"^\s+(CKM_[A-Z0-9_]+)")

#: Mechanism-name fragments -> the algorithm family a CBOM cares about.
_MECHANISM_FAMILIES: tuple[tuple[str, str], ...] = (
    ("ML_KEM", "ML-KEM"), ("KYBER", "ML-KEM"),
    ("ML_DSA", "ML-DSA"), ("DILITHIUM", "ML-DSA"),
    ("SLH_DSA", "SLH-DSA"), ("SPHINCS", "SLH-DSA"),
    ("FN_DSA", "FN-DSA"), ("FALCON", "FN-DSA"),
    ("HQC", "HQC"), ("BIKE", "BIKE"), ("CLASSIC_MCELIECE", "Classic McEliece"),
    ("AES", "AES"), ("DES3", "3DES"), ("DES", "DES"), ("CAST5", "CAST5"),
    ("CAMELLIA", "Camellia"), ("ARIA", "ARIA"), ("SEED", "SEED"), ("SM4", "SM4"),
    ("RSA", "RSA"), ("DSA", "DSA"), ("ECDSA", "ECDSA"), ("EDDSA", "EdDSA"),
    ("ECDH", "ECDH"), ("DH", "DH"), ("EC", "EC"), ("SHA3", "SHA-3"),
    ("SHA512", "SHA-512"), ("SHA384", "SHA-384"), ("SHA256", "SHA-256"),
    ("SHA224", "SHA-224"), ("SHA_1", "SHA-1"), ("MD5", "MD5"),
    ("GOST", "GOST"), ("CHACHA20", "ChaCha20"), ("POLY1305", "Poly1305"),
)

#: Families that are post-quantum. Kept separate so drift can say "PQC appeared"
#: without re-deriving it from a string every time.
PQC_FAMILIES = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC", "BIKE",
                          "Classic McEliece"})


class PinOnCommandLineRefused(RuntimeError):
    """A caller tried to put the partition PIN into argv."""


class CommandNotAllowed(RuntimeError):
    """A binary or argument outside the allowlist was requested."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    available: bool = True

    def failed(self) -> bool:
        return self.returncode != 0 or not self.available


def build_argv(*argv: str) -> tuple[str, ...]:
    if not argv or Path(argv[0]).name not in ALLOWED_BINARIES:
        raise CommandNotAllowed(
            f"{argv[0] if argv else '<empty>'!r} is not allowlisted; this reader runs "
            f"{sorted(ALLOWED_BINARIES)} only")
    for part in argv:
        if not isinstance(part, str) or not _ARGUMENT.match(part):
            raise CommandNotAllowed(f"argument {part!r} is not a plain argv element")
        if part.startswith("--pin"):
            raise PinOnCommandLineRefused(
                "the PIN is passed through the environment, never on argv: argv is "
                "world-readable in ps")
    return tuple(argv)


def validate_module_path(path: str) -> str:
    """The PKCS#11 module must be an absolute path to a regular file."""
    candidate = Path(path or "")
    if not candidate.is_absolute() or not candidate.name or ".." in candidate.parts:
        raise CommandNotAllowed(
            f"{path!r} is not an absolute module path; a relative or traversing path "
            "would let a caller load any library into the agent")
    if not candidate.is_file():
        raise CommandNotAllowed(f"{path!r} is not a file on this host")
    return str(candidate)


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #

def _is_placeholder(value: str) -> bool:
    return value.strip().lower() in {"", "unknown", "<empty>", "no label", "none"}


def parse_token_info(text: str) -> list[dict[str, Any]]:
    """``pkcs11-tool -T`` output -> one record per slot holding a token."""
    tokens: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in (text or "").splitlines():
        slot = _SLOT_LINE.match(line.strip())
        if slot:
            current = {"slot": int(slot.group(1)), "slot_description": slot.group(2).strip()}
            tokens.append(current)
            continue
        if current is None:
            continue
        field_match = _FIELD_LINE.match(line)
        if not field_match:
            continue
        name = field_match.group(1).strip().lower()
        value = field_match.group(2).strip()
        current[name] = value
    return [_normalise_token(token) for token in tokens if _has_token(token)]


def _has_token(token: dict[str, Any]) -> bool:
    return any(key.startswith(("token ", "hardware version", "firmware version"))
               and not _is_placeholder(str(value))
               for key, value in token.items())


def _normalise_token(token: dict[str, Any]) -> dict[str, Any]:
    flags = str(token.get("token flags", "") or "")
    clean_flags = [flag.strip() for flag in flags.split(",") if flag.strip()]
    return {
        "slot": token.get("slot"),
        "label": _clean(token.get("token label")) or token.get("slot_description"),
        "manufacturer": _clean(token.get("token manufacturer")),
        "model": _clean(token.get("token model")),
        "serial_reference": _clean(token.get("token serial")),
        "firmware": _clean(token.get("firmware version")),
        "hardware_version": _clean(token.get("hardware version")),
        "flags": clean_flags,
        # Posture a bank asks about, read from the token's own flags rather
        # than assumed from the vendor name.
        "login_required": any("login required" in flag for flag in clean_flags),
        "write_protected": any("write protected" in flag for flag in clean_flags),
        "initialized": any("token initialized" in flag for flag in clean_flags),
        "utc_time": _clean(token.get("utc time")),
    }


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if _is_placeholder(text) else text


def parse_mechanisms(text: str) -> list[str]:
    """``pkcs11-tool -M`` output -> the mechanism names, in the order given."""
    seen: list[str] = []
    for line in (text or "").splitlines():
        match = _MECHANISM_LINE.match(line)
        if match and match.group(1) not in seen:
            seen.append(match.group(1))
    return seen


def mechanism_families(mechanisms: Sequence[str]) -> list[str]:
    """Mechanism names -> algorithm families, deduplicated and ordered."""
    families: list[str] = []
    for mechanism in mechanisms:
        for fragment, family in _MECHANISM_FAMILIES:
            if fragment in mechanism and family not in families:
                families.append(family)
    return families


def pqc_families(families: Sequence[str]) -> list[str]:
    return [family for family in families if family in PQC_FAMILIES]


# --------------------------------------------------------------------------- #
# the reader
# --------------------------------------------------------------------------- #

@dataclass
class HsmReadResult:
    """What a vendor-neutral reader can honestly say about one appliance."""

    source: str
    manufacturer: str | None = None
    model: str | None = None
    serial_reference: str | None = None
    firmware: str | None = None
    partitions: list[dict[str, Any]] = field(default_factory=list)
    mechanisms: list[str] = field(default_factory=list)
    algorithms: list[str] = field(default_factory=list)
    pqc_algorithms: list[str] = field(default_factory=list)
    login_required: bool | None = None
    write_protected: bool | None = None
    capabilities: list[str] = field(default_factory=list)
    commands: list[tuple[str, ...]] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)

    def to_raw(self) -> dict[str, Any]:
        """The raw shape :class:`~universal_vendor.hardware.hsm_hw.HsmHardwareScanner` reads.

        Readers feed the one scanner; they do not invent a second observation
        shape, which is the same rule the HBOM projection follows.
        """
        return {
            "manufacturer": self.manufacturer or "",
            "model": self.model or "",
            "firmware": self.firmware,
            "serial_reference": self.serial_reference,
            "cluster": None,
            "partition_metadata": {"partitions": self.partitions,
                                   "count": len(self.partitions)},
            "supported_algorithms": list(self.algorithms),
            "pqc_algorithms": list(self.pqc_algorithms),
            "pqc_capability": ("SUPPORTED" if self.pqc_algorithms else "NOT_SUPPORTED"
                              if self.mechanisms else "UNKNOWN"),
            "crypto_capabilities": list(self.capabilities),
            "pkcs11_mechanisms": list(self.mechanisms),
            "security_posture": {"login_required": self.login_required,
                                 "write_protected": self.write_protected},
            "key_type_metadata": [],
            "certificate_dependencies": [],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "source": self.source,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial_reference": self.serial_reference,
            "firmware": self.firmware,
            "partitions": self.partitions,
            "mechanisms": list(self.mechanisms),
            "algorithms": list(self.algorithms),
            "pqc_algorithms": list(self.pqc_algorithms),
            "login_required": self.login_required,
            "write_protected": self.write_protected,
            "capabilities": list(self.capabilities),
            "unavailable": list(self.unavailable),
            "commands": [list(argv) for argv in self.commands],
        }


class Pkcs11Reader:
    """Read one HSM through PKCS#11, with the PIN kept out of argv."""

    def __init__(self, runner: Any = None, timeout: float = 10.0,
                 environ: Mapping[str, str] | None = None) -> None:
        self._runner = runner or self._subprocess_runner
        self.timeout = timeout
        self._environ = environ if environ is not None else os.environ

    # -- execution ------------------------------------------------------- #

    def _run(self, argv: tuple[str, ...], env: dict[str, str]) -> CommandResult:
        return self._runner(argv, self.timeout, env)

    def _subprocess_runner(self, argv: Sequence[str], timeout: float,
                           env: dict[str, str]) -> CommandResult:
        binary = shutil.which(argv[0])
        if binary is None:
            return CommandResult(tuple(argv), 127, "", f"{argv[0]} is not installed",
                                 available=False)
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, shell=False
                [binary, *argv[1:]], capture_output=True, text=True, timeout=timeout,
                check=False, shell=False, env={**os.environ, **env},
            )
        except subprocess.TimeoutExpired:
            return CommandResult(tuple(argv), 124, "", f"timed out after {timeout:g}s")
        except OSError as exc:  # noqa: BLE001 - binary vanished or was denied
            return CommandResult(tuple(argv), 126, "", str(exc), available=False)
        return CommandResult(tuple(argv), completed.returncode, completed.stdout,
                             completed.stderr)

    # -- collection ------------------------------------------------------ #

    def collect(self, module: str, *, pin_env: str | None = PIN_ENV) -> HsmReadResult:
        """Read token info and the mechanism list.

        ``pin_env`` names the environment variable holding the PIN. It is passed
        through and never read into this process's memory beyond the child's
        environment.
        """
        result = HsmReadResult(source="pkcs11")
        module_path = validate_module_path(module)
        env: dict[str, str] = {}
        if pin_env and self._environ.get(pin_env):
            env[pin_env] = self._environ[pin_env]
        else:
            result.unavailable.append(
                f"{pin_env or PIN_ENV} is not set: token metadata below the login state "
                "is still readable, and the mechanism list may be empty")

        info = self._run(build_argv("pkcs11-tool", "--module", module_path, "-T"), env)
        result.commands.append(info.argv)
        if info.failed():
            result.unavailable.append(_reason("pkcs11-tool -T", info))
            return result
        tokens = parse_token_info(info.stdout)
        if not tokens:
            result.unavailable.append(
                "the module answered but listed no initialized token: an empty HSM is a "
                "fact worth recording, not a successful scan")
            return result

        result.partitions = tokens
        primary = tokens[0]
        result.manufacturer = primary.get("manufacturer")
        result.model = primary.get("model")
        result.serial_reference = primary.get("serial_reference")
        result.firmware = primary.get("firmware")
        result.login_required = primary.get("login_required")
        result.write_protected = primary.get("write_protected")
        if len(tokens) > 1:
            result.capabilities.append(f"{len(tokens)} partition(s) on one appliance")

        mechanisms = self._run(
            build_argv("pkcs11-tool", "--module", module_path, "-M"), env)
        result.commands.append(mechanisms.argv)
        if mechanisms.failed():
            result.unavailable.append(_reason("pkcs11-tool -M", mechanisms))
            return result
        result.mechanisms = parse_mechanisms(mechanisms.stdout)
        families = mechanism_families(result.mechanisms)
        result.algorithms = families
        result.pqc_algorithms = pqc_families(families)
        if not result.mechanisms:
            result.unavailable.append(
                "the mechanism list came back empty: the token refused the read, and an "
                "empty capability list is not the same as no capability")
        return result


def _reason(command: str, result: CommandResult) -> str:
    detail = (result.stderr or "").strip().splitlines()
    first = detail[0] if detail else f"exit {result.returncode}"
    if not result.available:
        return f"{command}: {first} (binary not installed)"
    lowered = first.lower()
    if "pin" in lowered or "login" in lowered or "c_[a-z]*_function_failed" in lowered:
        return f"{command}: {first} (the token needs a login this agent does not hold)"
    if "permission denied" in lowered:
        return f"{command}: {first} (the agent cannot open the module)"
    return f"{command}: {first}"

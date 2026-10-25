"""Least-privilege, offline, manifest-only metadata collection. No shell/network.

Linux uses descriptor-relative no-follow traversal; Windows pins each ancestor
with non-delete/non-write-shared handles and refuses reparse points. Neither
adapter recurses. Windows code still requires a real Windows qualification run.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath

from shared_models.host_collection import HostFact, HostManifest, HostReceipt, HostSnapshot, MAX_FACTS, digest


class Refused(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


def elevated():
    if sys.platform == "win32":
        try:
            return _windows_elevated()
        except (OSError, AttributeError):
            return True  # failed identity check cannot establish least privilege
    if os.geteuid() == 0 or os.geteuid() != os.getuid() or os.getegid() != os.getgid():
        return True
    if not sys.platform.startswith("linux"):
        return True
    import ctypes

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Cap(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]

    header, caps = Header(0x20080522, 0), (Cap * 2)()
    try:
        return ctypes.CDLL(None).capget(ctypes.byref(header), ctypes.byref(caps)) != 0 or any(
            c.effective or c.permitted for c in caps
        )
    except (OSError, AttributeError):
        return True


def _windows_elevated():
    import ctypes
    from ctypes import wintypes as w

    kernel, adv = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("advapi32", use_last_error=True)
    current = kernel.GetCurrentProcess
    current.argtypes, current.restype = [], w.HANDLE
    open_token = adv.OpenProcessToken
    open_token.argtypes, open_token.restype = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL
    query = adv.GetTokenInformation
    query.argtypes, query.restype = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL
    close = kernel.CloseHandle
    close.argtypes, close.restype = [w.HANDLE], w.BOOL
    token = w.HANDLE()
    if not open_token(current(), 8, ctypes.byref(token)):
        return True
    try:
        size, elevation = w.DWORD(), w.DWORD()
        if not query(token, 20, ctypes.byref(elevation), 4, ctypes.byref(size)) or elevation.value:
            return True
        # No privilege-enabling calls. Refuse enabled backup/debug/impersonate
        # privileges even for non-administrator service/backup accounts.
        buffer = ctypes.create_string_buffer(4096)
        if not query(token, 3, buffer, len(buffer), ctypes.byref(size)):
            return True

        class Luid(ctypes.Structure):
            _fields_ = [("low", w.DWORD), ("high", w.LONG)]

        class Priv(ctypes.Structure):
            _fields_ = [("luid", Luid), ("attributes", w.DWORD)]

        lookup = adv.LookupPrivilegeValueW
        lookup.argtypes, lookup.restype = [w.LPCWSTR, w.LPCWSTR, ctypes.POINTER(Luid)], w.BOOL
        benign = Luid()
        if not lookup(None, "SeChangeNotifyPrivilege", ctypes.byref(benign)):
            return True
        count = w.DWORD.from_buffer(buffer).value
        if count > 128 or 4 + count * ctypes.sizeof(Priv) > size.value:
            return True
        for index in range(count):
            privilege = Priv.from_buffer_copy(buffer, 4 + index * ctypes.sizeof(Priv))
            if privilege.attributes & 2 and (privilege.luid.low, privilege.luid.high) != (benign.low, benign.high):
                return True
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    finally:
        close(token)


def _parts(path, windows=False):
    p = PureWindowsPath(path) if windows else PurePosixPath(path)
    if not p.is_absolute() or ".." in p.parts or len(p.parts) > 64:
        raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
    if windows and (
        not re.fullmatch(r"[A-Za-z]:", p.drive)
        or any(
            ":" in x or x.endswith((".", " ")) or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", x)
            for x in p.parts[1:]
        )
    ):
        raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
    if not windows and path.startswith("//"):
        raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
    return p


@contextmanager
def _linux_fd(path):
    p = _parts(path)
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in p.parts[1:-1]:
            nxt = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        leaf = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(leaf)
            # Hard links, device/FIFO/socket inputs and proc/sys pseudo-files are
            # not collection shortcuts. Hard-link refusal also limits aliasing.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
            import ctypes

            fs = ctypes.create_string_buffer(256)
            if ctypes.CDLL(None).fstatfs(leaf, ctypes.byref(fs)) != 0 or ctypes.c_long.from_buffer(
                fs
            ).value & 0xFFFFFFFF not in {
                0xEF53,
                0x58465342,
                0x9123683E,
                0x01021994,
                0x794C7630,
                0x2FC12FC1,
                0x73717368,
                0x858458F6,
            }:
                raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
            yield leaf
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


@contextmanager
def _windows_fd(path):
    import ctypes
    from ctypes import wintypes as w
    import msvcrt

    p = _parts(path, windows=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    create.restype = w.HANDLE
    close = kernel.CloseHandle
    close.argtypes, close.restype = [w.HANDLE], w.BOOL

    class Info(ctypes.Structure):
        _fields_ = [
            ("attributes", w.DWORD),
            ("creation", w.FILETIME),
            ("access", w.FILETIME),
            ("write", w.FILETIME),
            ("volume", w.DWORD),
            ("size_high", w.DWORD),
            ("size_low", w.DWORD),
            ("links", w.DWORD),
            ("index_high", w.DWORD),
            ("index_low", w.DWORD),
        ]

    inspect = kernel.GetFileInformationByHandle
    inspect.argtypes, inspect.restype = [w.HANDLE, ctypes.POINTER(Info)], w.BOOL
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes, drive_type.restype = [w.LPCWSTR], w.UINT
    if drive_type(p.anchor) != 3:  # fixed local disk only; no mapped/UNC/network drives
        raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
    handles, fd = [], None
    try:
        # Keep EVERY ancestor pinned until the leaf is closed. SHARE_READ only:
        # existing write/delete handles cause refusal, never a permissive retry.
        current = p.anchor
        for index, part in enumerate(("", *p.parts[1:])):
            if part:
                current = str(PureWindowsPath(current) / part)
            final = index == len(p.parts) - 1
            handle = create(current, 0x80000000 if final else 0x80, 1, None, 3, 0x00200000 | 0x02000000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
            info = Info()
            if not inspect(handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & 0x400 or (final and (info.attributes & 0x10 or info.links != 1)):
                raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
        # open_osfhandle takes ownership. Do not double-close its HANDLE.
        fd = msvcrt.open_osfhandle(handles[-1], os.O_RDONLY | os.O_BINARY)
        handles.pop()
        yield fd
    finally:
        if fd is not None:
            os.close(fd)
        for handle in reversed(handles):
            close(handle)


def _read(path, limit, charge):
    if sys.platform.startswith("linux") and (_parts(path).parts[1:2] in [("proc",), ("sys",), ("dev",)]):
        raise Refused("UNSUPPORTED", "SYMLINK_OR_SPECIAL")
    opener = _windows_fd if sys.platform == "win32" else _linux_fd
    with opener(path) as fd:
        before = os.fstat(fd)
        if before.st_size > limit:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        data = bytearray()
        while len(data) < limit:
            chunk = os.read(fd, min(65536, limit - len(data)))
            if not chunk:
                break
            charge(len(chunk))
            data.extend(chunk)
        if len(data) > limit:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(data) != after.st_size:
            raise Refused("INVALID", "INPUT_CHANGED")
        return bytes(data)


def _certificate(data):
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        return _certificate_metadata(data)
    except (x509.InvalidVersion, x509.DuplicateExtension, UnsupportedAlgorithm):
        raise Refused("UNSUPPORTED", "INVALID_FORMAT") from None


def _certificate_metadata(data):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

    # Exactly one public certificate, not a bundle/private-key container.
    if data.lstrip().startswith(b"-----BEGIN"):
        if not re.fullmatch(rb"\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*", data):
            raise Refused("INVALID", "INVALID_FORMAT")
        cert = x509.load_pem_x509_certificate(data)
    else:
        # pyca may accept trailing DER bytes; enforce canonical single object.
        from cryptography.hazmat.primitives.serialization import Encoding

        cert = x509.load_der_x509_certificate(data)
        if cert.public_bytes(Encoding.DER) != data:
            raise Refused("INVALID", "INVALID_FORMAT")
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        key = cert.public_key()
    except UnsupportedAlgorithm:
        key = None
    algorithm, size, curve = "UNKNOWN", None, "UNKNOWN"
    for cls, name in (
        (rsa.RSAPublicKey, "RSA"),
        (ec.EllipticCurvePublicKey, "EC"),
        (dsa.DSAPublicKey, "DSA"),
        (ed25519.Ed25519PublicKey, "ED25519"),
        (ed448.Ed448PublicKey, "ED448"),
    ):
        if isinstance(key, cls):
            algorithm, size = name, getattr(key, "key_size", None)
            if name == "EC" and key.curve.name in {"secp256r1", "secp384r1", "secp521r1"}:
                curve = key.curve.name
            break
    try:
        signature = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"
    except Exception:
        signature = "UNKNOWN"
    if signature not in {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}:
        signature = "UNKNOWN"
    return [
        HostFact(
            kind="CERTIFICATE",
            local_basis="OBSERVED",
            purpose="PUBLIC_KEY_METADATA",
            algorithm=algorithm,
            key_size=size,
            curve=curve,
            signature_hash=signature,
            certificate_signature_oid=getattr(
                getattr(cert, "signature_algorithm_oid", None), "dotted_string", "UNKNOWN"
            ),
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        )
    ]


def _config(data):
    from shared_models.host_collection import Protocol, Cipher
    from typing import get_args

    protocols, ciphers, unknown, found = [], [], False, False
    for line in data.decode("utf-8", errors="strict").splitlines():
        line = line.split("#", 1)[0].strip()
        match = re.fullmatch(r"(ssl_protocols|ssl_ciphers)\s+([^;{}]+);", line)
        if not match:
            if re.search(r"\b(ssl_protocols|ssl_ciphers|include)\b", line):
                unknown = True
            continue
        found = True
        key, value = match.groups()
        values = value.strip("\"'").split() if key == "ssl_protocols" else value.strip("\"'").split(":")
        allowed = get_args(Protocol) if key == "ssl_protocols" else get_args(Cipher)
        target = protocols if key == "ssl_protocols" else ciphers
        for token in values:
            if token not in allowed:
                unknown = True
            elif token not in target:
                target.append(token)
    if not found and not unknown:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    return [
        HostFact(
            kind="TLS_CONFIGURATION",
            local_basis="DECLARED",
            purpose="TLS_CONFIGURATION",
            protocols=protocols,
            cipher_suites=ciphers,
            unparsed_directives=unknown,
        )
    ]


def _packages(data):
    from inventory.linux_packages import dpkg_status

    return dpkg_status(data)


def _os_release(data):
    """Read two literal allowlisted fields. NEVER source/expand an os-release file."""
    values = {}
    for line in data.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in {"ID", "VERSION_ID"}:
            continue
        if key in values:
            raise Refused("INVALID", "INVALID_FORMAT")
        match = re.fullmatch(r"(?:'([A-Za-z0-9_.-]{1,64})'|\"([A-Za-z0-9_.-]{1,64})\"|([A-Za-z0-9_.-]{1,64}))", value)
        if not match:
            raise Refused("INVALID", "INVALID_FORMAT")
        values[key] = next(v for v in match.groups() if v is not None)
    if "ID" not in values:
        raise Refused("INVALID", "INVALID_FORMAT")
    return [
        HostFact(
            kind="OS_RELEASE",
            local_basis="DECLARED",
            purpose="OS_RELEASE_METADATA",
            software_name=values["ID"],
            software_version=values.get("VERSION_ID"),
        )
    ]


def _registry_value(item, field):
    # Fixed-size native buffer: winreg.QueryValueEx allocates an unbounded value
    # before the caller can check its size. Never use it for host collection.
    import ctypes
    from ctypes import wintypes as w

    query = ctypes.WinDLL("advapi32", use_last_error=True).RegQueryValueExW
    query.argtypes = [w.HKEY, w.LPCWSTR, w.LPVOID, ctypes.POINTER(w.DWORD), w.LPVOID, ctypes.POINTER(w.DWORD)]
    query.restype = w.LONG
    value, typ, size = ctypes.create_unicode_buffer(121), w.DWORD(), w.DWORD(242)
    result = query(int(item), field, None, ctypes.byref(typ), value, ctypes.byref(size))
    if result == 2:
        raise FileNotFoundError
    if result == 234:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    if result or typ.value != 1 or size.value > 242 or size.value % 2 or not value.value:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    return value.value


def _registry(path, limit):
    # Only approved uninstall inventory branches. No arbitrary registry values,
    # autorun commands, product uninstall strings, credentials or remote registry.
    import winreg

    allowed = {
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    }
    if path not in allowed:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    facts = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path[5:], 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
        count = winreg.QueryInfoKey(root)[0]
        if count > MAX_FACTS:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        for index in range(count):
            name = winreg.EnumKey(root, index)
            with winreg.OpenKey(root, name, 0, winreg.KEY_READ) as item:
                values = []
                for field in ("DisplayName", "DisplayVersion"):
                    try:
                        values.append(_registry_value(item, field))
                    except FileNotFoundError:
                        values.append(None)
                if values[0]:
                    facts.append(
                        HostFact(
                            kind="SOFTWARE",
                            local_basis="OBSERVED",
                            purpose="PACKAGE_DATABASE_RECORD",
                            software_name=values[0],
                            software_version=values[1],
                        )
                    )
    if not facts:
        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
    # Registry receipt commits only the bounded allowlisted value projection.
    import json

    data = json.dumps([f.model_dump(mode="json") for f in facts], sort_keys=True).encode()
    if len(data) > limit:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    return data, facts


def collect(manifest: HostManifest) -> HostSnapshot:
    started = datetime.now(timezone.utc)
    platform = "windows" if sys.platform == "win32" else "linux" if sys.platform.startswith("linux") else "unsupported"
    receipts, total, fact_count = [], 0, 0
    for item in manifest.inputs:
        consumed = 0

        def charge(count):
            nonlocal total, consumed
            total += count
            consumed += count

        try:
            if platform != manifest.platform:
                raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
            if elevated():
                raise Refused("DENIED", "LEAST_PRIVILEGE_UNPROVEN")
            if datetime.now(timezone.utc) >= manifest.expires_at:
                raise Refused("DENIED", "EXPIRED")
            limit = min(manifest.max_file_bytes, manifest.max_total_bytes - total)
            if limit <= 0 or fact_count >= MAX_FACTS:
                raise Refused("BUDGET_EXCEEDED", "LIMIT")
            if item.kind.startswith("LINUX_") and item.kind != "LINUX_OS_RELEASE":
                if platform != "linux":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.linux_runtime import collect_live, ProbeError

                try:
                    data, facts = collect_live(item, limit, charge)
                except ProbeError as exc:
                    raise Refused(exc.status, exc.reason) from None
            elif item.kind == "WINDOWS_OS_RELEASE":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_runtime import collect_os_version

                data, facts = collect_os_version(item, limit, charge)
            elif item.kind == "WINDOWS_CAPI_DEFAULT_PROVIDER":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_capi import collect_default_provider

                data, facts = collect_default_provider(item, limit, charge)
            elif item.kind == "WINDOWS_TCP_LISTENERS":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_listeners import collect_listeners

                data, facts = collect_listeners(item, limit, charge)
            elif item.kind == "WINDOWS_TPM_DEVICE_INFO":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_tpm import collect_device

                data, facts = collect_device(item, limit, charge)
            elif item.kind == "WINDOWS_CNG_REGISTRATION":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_cng import collect_registration

                data, facts = collect_registration(item, limit, charge)
            elif item.kind == "WINDOWS_PROCESS_MODULES":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_images import collect_images

                data, facts = collect_images(item, limit, charge)
            elif item.kind == "WINDOWS_CERTIFICATE":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_certificates import collect_certificate

                data, facts = collect_certificate(item, limit, charge)
            elif item.kind == "WINDOWS_SERVICE":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                from inventory.windows_runtime import collect_service

                data, facts = collect_service(item, limit, charge)
            elif item.kind == "WINDOWS_UNINSTALL":
                if platform != "windows":
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                data, facts = _registry(item.path, limit)
                charge(len(data))
            else:
                if (
                    item.kind in {"DPKG_STATUS", "APK_INSTALLED", "RPM_SQLITE", "LINUX_OS_RELEASE"}
                    and platform != "linux"
                ):
                    raise Refused("UNSUPPORTED", "UNSUPPORTED_PLATFORM")
                data = _read(item.path, limit, charge)
                if b"PRIVATE KEY" in data or b"BEGIN OPENSSH" in data:
                    raise Refused("INVALID", "PRIVATE_MATERIAL_REFUSED")
                if item.kind == "PUBLIC_CERTIFICATE":
                    facts = _certificate(data)
                elif item.kind == "NGINX_TLS_CONFIG":
                    facts = _config(data)
                elif item.kind == "DPKG_STATUS":
                    facts = _packages(data)
                elif item.kind == "RPM_SQLITE":
                    from inventory.rpm_metadata import rpm_sqlite

                    facts = rpm_sqlite(data)
                elif item.kind == "APK_INSTALLED":
                    from inventory.linux_packages import apk_installed

                    facts = apk_installed(data)
                elif item.kind == "LINUX_OS_RELEASE":
                    facts = _os_release(data)
                else:
                    fmt = "ELF" if data.startswith(b"\x7fELF") else "PE" if data.startswith(b"MZ") else None
                    if fmt is None:
                        raise Refused("UNSUPPORTED", "INVALID_FORMAT")
                    facts = [
                        HostFact(kind="BINARY", local_basis="OBSERVED", purpose="FILE_PRESENCE", binary_format=fmt)
                    ]
            if fact_count + len(facts) > MAX_FACTS:
                raise Refused("BUDGET_EXCEEDED", "LIMIT")
            if datetime.now(timezone.utc) >= manifest.expires_at:
                raise Refused("DENIED", "EXPIRED")
            fact_count += len(facts)
            receipt = HostReceipt(
                input_id=item.input_id,
                status="PARSED",
                reason="METADATA_ONLY",
                byte_count=consumed,
                content_sha256=hashlib.sha256(data).hexdigest(),
                facts=facts,
            )
        except Refused as exc:
            receipt = HostReceipt(input_id=item.input_id, status=exc.status, reason=exc.reason)
        except PermissionError:
            receipt = HostReceipt(input_id=item.input_id, status="DENIED", reason="ACCESS_DENIED")
        except FileNotFoundError:
            receipt = HostReceipt(input_id=item.input_id, status="UNAVAILABLE", reason="NOT_FOUND")
        except OSError:
            receipt = HostReceipt(input_id=item.input_id, status="UNSUPPORTED", reason="SYMLINK_OR_SPECIAL")
        except (ValueError, KeyError, TypeError):
            receipt = HostReceipt(input_id=item.input_id, status="INVALID", reason="INVALID_FORMAT")
        if receipt.status != "PARSED":
            receipt = receipt.model_copy(update={"byte_count": consumed})
        receipts.append(receipt)
    return HostSnapshot(
        manifest=manifest,
        manifest_sha256=digest(manifest),
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        execution_platform=platform,
        receipts=receipts,
    )

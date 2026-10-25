"""Windows candidate: exact local public certificate, no enumeration/private keys.

SHA-1 is only the native store locator, never a trust/crypto-use assertion. Both
locator and required SHA-256 binding are checked against canonical public DER.
Native API latency/internal allocations remain Windows qualification gates.
"""

import ctypes
import hashlib
import sys
from shared_models.host_runtime_scope import certificate_resource


# Fixed-width DWORDs and pointer-width fields, not host-dependent c_ulong.
class HashBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class CertificateContext(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", ctypes.c_uint32),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", ctypes.c_uint32),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


X509_ASN_ENCODING = 0x1
ENCODINGS = 0x10001  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
CERT_STORE_PROV_SYSTEM_W = 10
CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
CERT_STORE_READONLY_FLAG = 0x8000
CERT_FIND_SHA1_HASH = 0x10000
CRYPT_E_NOT_FOUND = 0x80092004
LOCATIONS = {"current-user": 0x10000, "local-machine": 0x20000}


def _api():
    if sys.platform != "win32":
        raise ValueError("Certificate stores require native Windows")
    api = ctypes.WinDLL("crypt32.dll", use_last_error=True, winmode=0x00000800)  # LOAD_LIBRARY_SEARCH_SYSTEM32
    api.CertOpenStore.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
    api.CertOpenStore.restype = ctypes.c_void_p
    api.CertFindCertificateInStore.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(CertificateContext),
    ]
    api.CertFindCertificateInStore.restype = ctypes.POINTER(CertificateContext)
    api.CertFreeCertificateContext.argtypes = [ctypes.POINTER(CertificateContext)]
    api.CertFreeCertificateContext.restype = ctypes.c_int32
    api.CertCloseStore.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    api.CertCloseStore.restype = ctypes.c_int32
    return api


def _error():
    code = ctypes.get_last_error() & 0xFFFFFFFF
    if code == 5:
        raise PermissionError("Certificate store query denied")
    if code in {2, 3, CRYPT_E_NOT_FOUND}:
        raise FileNotFoundError("Approved certificate/store unavailable")
    from inventory.host import Refused

    raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")


def read_certificate(path, limit, charge):
    """Copy at most one approved DER object; retain no native handles after return.

    A second matching native context is refused as ambiguous. The documented
    pPrevCertContext ownership transfer is respected even on a failed find.
    """
    from inventory.host import Refused

    location, store_name, sha1, sha256 = certificate_resource(path)
    # Reserve caller-owned fixed buffers before opening any native interface.
    reserved = ctypes.sizeof(HashBlob) + 20 + ctypes.sizeof(CertificateContext) + (len(store_name) + 1) * 2
    if limit <= reserved:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    charge(reserved)
    api = _api()
    locator = (ctypes.c_ubyte * 20).from_buffer_copy(bytes.fromhex(sha1))
    blob = HashBlob(20, locator)
    store_buffer = ctypes.create_unicode_buffer(store_name)
    store = api.CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | LOCATIONS[location],
        ctypes.cast(store_buffer, ctypes.c_void_p),
    )
    if not store:
        _error()
    context = None
    try:
        context = api.CertFindCertificateInStore(store, ENCODINGS, 0, CERT_FIND_SHA1_HASH, ctypes.byref(blob), None)
        if not context:
            _error()
        view = context.contents
        size = view.cbCertEncoded
        if not size or not view.pbCertEncoded or view.dwCertEncodingType not in {X509_ASN_ENCODING, ENCODINGS}:
            raise Refused("INVALID", "INVALID_FORMAT")
        if size > limit - reserved:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        charge(size)  # Before copying native DER into Python memory.
        data = ctypes.string_at(view.pbCertEncoded, size)
        if hashlib.sha1(data).hexdigest() != sha1 or hashlib.sha256(data).hexdigest() != sha256:
            raise Refused("INVALID", "INPUT_CHANGED")
        # Native find frees the supplied previous context even when not found.
        previous, context = context, None
        context = api.CertFindCertificateInStore(store, ENCODINGS, 0, CERT_FIND_SHA1_HASH, ctypes.byref(blob), previous)
        if context:
            raise Refused("INVALID", "INVALID_FORMAT")
        if ctypes.get_last_error() & 0xFFFFFFFF != CRYPT_E_NOT_FOUND:
            _error()  # Denied/error is not proof that the result was unique.
        return data
    finally:
        try:
            if context and not api.CertFreeCertificateContext(context):
                raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")
        finally:
            if not api.CertCloseStore(store, 0):
                raise Refused("UNAVAILABLE", "INTERFACE_UNAVAILABLE")


def collect_certificate(item, limit, charge):
    from inventory.host import _certificate

    data = read_certificate(item.path, limit, charge)
    return data, _certificate(data)  # Strict canonical public DER, no PFX/private bodies.

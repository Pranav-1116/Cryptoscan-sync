"""PE / .NET assembly scanner — crypto inventory for vendored ``.dll`` / ``.exe`` without source.

Two independent sources of evidence, both read straight from the PE file (no
``ildasm``, no dotnet SDK):

1. **.NET metadata** (CLI header → metadata root → ``#Strings`` identifier heap and
   ``#US`` user-string heap). Type names referenced by the assembly
   (``Aes``, ``TripleDESCryptoServiceProvider``, ``Rfc2898DeriveBytes``, ``SslStream`` …)
   are only reported when the matching namespace (``System.Security.Cryptography``,
   ``System.Net.Security``, ``Org.BouncyCastle.*`` …) is also present — an app that
   names its own class ``RSA`` in a different namespace is not counted. String literals
   (``"SHA256"``, ``"HS256"``, ``"AES/CBC/PKCS7"``, XML-DSig URIs) are classified with
   the same vocabulary the JAR scanner uses.
2. **PE import table** for native binaries: CNG (``BCryptEncrypt``), CAPI
   (``CryptAcquireContextA``), Schannel, OpenSSL (``EVP_aes_256_gcm``,
   ``SSL_CTX_new``), libsodium, mbedTLS, wolfSSL symbols. Names only — a native DLL
   importing ``BCryptEncrypt`` proves the API is linked, not which algorithm is
   configured, so such findings are MEDIUM at best.

Every finding carries ``code_origin="archive"`` and a ``file_path`` of the form
``vendor/x.dll!Namespace.Type`` / ``x.dll!import:BCryptEncrypt`` so the reviewer can see
exactly what was matched.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import re
import struct
from pathlib import Path

from scanner.extractors.algorithm_extractor import known_algorithm_or_unknown, parse_transformation
from scanner.models.raw_finding import CryptoInfo, FindingMetadata, RawFinding, SourceLocation

SCANNER_ID = "static-dotnet-assembly-scanner-v1.0"
ASSEMBLY_SUFFIXES = (".dll", ".exe", ".netmodule", ".winmd")

# ----------------------------------------------------------------------------- PE parsing


class _PE:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ" or len(data) < 0x40:
            raise ValueError("not a PE file")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        coff = pe + 4
        nsect, opt_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        dd_off = opt + (96 if magic == 0x10B else 112)
        ndirs = struct.unpack_from("<I", data, dd_off - 4)[0]
        self.dirs = [struct.unpack_from("<II", data, dd_off + 8 * i) for i in range(min(ndirs, 16))]
        sect = opt + opt_size
        self.sections = []
        for i in range(nsect):
            base = sect + 40 * i
            if base + 40 > len(data):
                break
            vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, base + 8)
            self.sections.append((vaddr, max(vsize, rsize), raw, rsize))

    def rva(self, rva: int) -> int | None:
        for vaddr, vsize, raw, rsize in self.sections:
            if vaddr <= rva < vaddr + vsize:
                off = raw + (rva - vaddr)
                return off if off < len(self.data) else None
        return None

    def cstr(self, off: int, limit: int = 512) -> str:
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            end = off + limit
        return self.data[off:end].decode("utf-8", errors="replace")

    # -- .NET metadata --------------------------------------------------------
    def dotnet_heaps(self) -> tuple[list[str], list[str]] | None:
        if len(self.dirs) < 15 or self.dirs[14][0] == 0:
            return None
        cli = self.rva(self.dirs[14][0])
        if cli is None:
            return None
        md_rva, md_size = struct.unpack_from("<II", self.data, cli + 8)
        md = self.rva(md_rva)
        if md is None or self.data[md : md + 4] != b"BSJB":
            return None
        vlen = struct.unpack_from("<I", self.data, md + 12)[0]
        p = md + 16 + vlen
        nstreams = struct.unpack_from("<H", self.data, p + 2)[0]
        p += 4
        strings: list[str] = []
        user: list[str] = []
        for _ in range(nstreams):
            off, size = struct.unpack_from("<II", self.data, p)
            name_end = self.data.find(b"\0", p + 8)
            name = self.data[p + 8 : name_end].decode("ascii", errors="replace")
            p = name_end + 1
            p = (p + 3) & ~3
            blob = self.data[md + off : md + off + size]
            if name == "#Strings":
                strings = [s.decode("utf-8", errors="replace") for s in blob.split(b"\0") if s]
            elif name == "#US":
                user = _read_us_heap(blob)
        return strings, user

    # -- import table ---------------------------------------------------------
    def imports(self) -> list[tuple[str, str]]:
        if len(self.dirs) < 2 or self.dirs[1][0] == 0:
            return []
        p = self.rva(self.dirs[1][0])
        if p is None:
            return []
        pe64 = struct.unpack_from("<H", self.data, struct.unpack_from("<I", self.data, 0x3C)[0] + 24)[0] == 0x20B
        out: list[tuple[str, str]] = []
        for _ in range(512):
            if p + 20 > len(self.data):
                break
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", self.data, p)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            p += 20
            dll_off = self.rva(name_rva)
            dll = self.cstr(dll_off).lower() if dll_off is not None else "?"
            thunk = self.rva(oft or ft)
            if thunk is None:
                continue
            for _ in range(4096):
                if pe64:
                    if thunk + 8 > len(self.data):
                        break
                    val = struct.unpack_from("<Q", self.data, thunk)[0]
                    thunk += 8
                    ordinal = val >> 63
                else:
                    if thunk + 4 > len(self.data):
                        break
                    val = struct.unpack_from("<I", self.data, thunk)[0]
                    thunk += 4
                    ordinal = val >> 31
                if val == 0:
                    break
                if ordinal:
                    continue
                hn = self.rva(val & 0x7FFFFFFF)
                if hn is not None:
                    out.append((dll, self.cstr(hn + 2, 256)))
        return out


def _read_us_heap(blob: bytes) -> list[str]:
    out: list[str] = []
    i = 1  # first byte is always 0
    n = len(blob)
    while i < n:
        b0 = blob[i]
        if b0 & 0x80 == 0:
            ln, i = b0, i + 1
        elif b0 & 0xC0 == 0x80:
            if i + 2 > n:
                break
            ln, i = ((b0 & 0x3F) << 8) | blob[i + 1], i + 2
        elif b0 & 0xE0 == 0xC0:
            if i + 4 > n:
                break
            ln, i = ((b0 & 0x1F) << 24) | (blob[i + 1] << 16) | (blob[i + 2] << 8) | blob[i + 3], i + 4
        else:
            break
        if ln == 0:
            continue
        chunk = blob[i : i + ln - 1]  # trailing flag byte excluded
        i += ln
        try:
            s = chunk.decode("utf-16-le", errors="replace")
        except Exception as _handler_exc:  # pragma: no cover
            logger.warning(
                "exception_suppressed",
                extra={"error_type": type(_handler_exc).__name__},
            )
            continue
        if s and len(s) <= 400:
            out.append(s)
    return out


# ----------------------------------------------------------------------------- .NET vocabulary

# namespace gate -> library label
_NAMESPACES = {
    "System.Security.Cryptography": "System.Security.Cryptography",
    "System.Security.Cryptography.X509Certificates": "System.Security.Cryptography",
    "System.Security.Cryptography.Xml": "System.Security.Cryptography.Xml",
    "System.Security.Cryptography.Pkcs": "System.Security.Cryptography.Pkcs",
    "System.Net.Security": "System.Net.Security",
    "System.Net": "System.Net",
    "System.IdentityModel.Tokens": "System.IdentityModel",
    "Microsoft.IdentityModel.Tokens": "Microsoft.IdentityModel",
    "System.IdentityModel.Tokens.Jwt": "System.IdentityModel.Tokens.Jwt",
    "Org.BouncyCastle.Crypto": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Engines": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Digests": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Generators": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Signers": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Agreement": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Macs": "BouncyCastle.NET",
    "Org.BouncyCastle.Crypto.Modes": "BouncyCastle.NET",
    "Org.BouncyCastle.Pqc.Crypto": "BouncyCastle.NET-PQC",
    "Org.BouncyCastle.Tls": "BouncyCastle.NET",
    "Org.BouncyCastle.OpenSsl": "BouncyCastle.NET",
    "Org.BouncyCastle.Pkcs": "BouncyCastle.NET",
    "Org.BouncyCastle.X509": "BouncyCastle.NET",
    "Konscious.Security.Cryptography": "Konscious.Argon2",
    "BCrypt.Net": "BCrypt.Net",
    "Sodium": "libsodium-net",
    "NSec.Cryptography": "NSec",
    "Isopoh.Cryptography.Argon2": "Isopoh.Argon2",
    "Scrypt": "Scrypt.NET",
    "CryptSharp": "CryptSharp",
    "Jose": "jose-jwt",
    "JWT": "jwt-dotnet",
    "JWT.Algorithms": "jwt-dotnet",
    "Microsoft.AspNetCore.DataProtection": "ASP.NET-DataProtection",
    "Microsoft.AspNetCore.Cryptography.KeyDerivation": "ASP.NET-KeyDerivation",
    "Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider": "AlwaysEncrypted",
    "Azure.Security.KeyVault.Keys.Cryptography": "AzureKeyVault",
    "Amazon.KeyManagementService": "AWS-KMS",
    "Google.Cloud.Kms.V1": "GCP-KMS",
    "Net.Pkcs11Interop": "Pkcs11Interop",
    "Net.Pkcs11Interop.HighLevelAPI": "Pkcs11Interop",
    "Thales.Luna": "HSM/Luna",
    "SafeNet.Luna": "HSM/Luna",
    "nCipher": "HSM/nCipher",
    "Utimaco": "HSM/Utimaco",
    "PaymentHSM": "HSM/payShield",
    "Thales.PayShield": "HSM/payShield",
    "Renci.SshNet": "SSH.NET",
    "Renci.SshNet.Security.Cryptography": "SSH.NET",
    "Renci.SshNet.Security.Cryptography.Ciphers": "SSH.NET",
    "Npgsql": "Npgsql",
    "MySql.Data.MySqlClient": "MySql.Data",
    "Oracle.ManagedDataAccess.Client": "ODP.NET",
    "StackExchange.Redis": "StackExchange.Redis",
    "Confluent.Kafka": "Confluent.Kafka",
    "RabbitMQ.Client": "RabbitMQ.Client",
    "IBM.WMQ": "IBM.WMQ",
    "IBM.XMS": "IBM.XMS",
}

# type name -> (algorithm, api_type, purpose, required namespace prefix, confidence)
_C, _D, _M, _S, _K, _KG, _TLS, _KDF = ("CIPHER_INSTANCE", "ENCRYPTION"), ("MESSAGE_DIGEST", "HASHING"), ("MAC", "MAC_GENERATION"), ("SIGNATURE", "SIGNING"), ("KEY_PAIR_GENERATOR", "KEY_GENERATION"), ("KEY_GENERATOR", "KEY_GENERATION"), ("KEY_AGREEMENT", "NETWORK_ENCRYPTION"), ("KEY_GENERATOR", "PASSWORD_HASHING")
_SSC = "System.Security.Cryptography"
_TYPES: dict[str, tuple[str, tuple[str, str], object, str]] = {
    # BCL symmetric
    "Aes": ("AES", _C, _SSC, "HIGH"), "AesManaged": ("AES", _C, _SSC, "HIGH"), "AesCryptoServiceProvider": ("AES", _C, _SSC, "HIGH"), "AesCng": ("AES", _C, _SSC, "HIGH"),
    "AesGcm": ("AES", _C, _SSC, "HIGH"), "AesCcm": ("AES", _C, _SSC, "HIGH"), "Rijndael": ("AES", _C, _SSC, "HIGH"), "RijndaelManaged": ("AES", _C, _SSC, "HIGH"),
    "ChaCha20Poly1305": ("ChaCha20-Poly1305", _C, _SSC, "HIGH"),
    "TripleDES": ("3DES", _C, _SSC, "HIGH"), "TripleDESCryptoServiceProvider": ("3DES", _C, _SSC, "HIGH"), "TripleDESCng": ("3DES", _C, _SSC, "HIGH"),
    "DES": ("DES", _C, _SSC, "HIGH"), "DESCryptoServiceProvider": ("DES", _C, _SSC, "HIGH"),
    "RC2": ("RC2", _C, _SSC, "HIGH"), "RC2CryptoServiceProvider": ("RC2", _C, _SSC, "HIGH"),
    # BCL hash / MAC / KDF
    "MD5": ("MD5", _D, _SSC, "HIGH"), "MD5CryptoServiceProvider": ("MD5", _D, _SSC, "HIGH"), "MD5Cng": ("MD5", _D, _SSC, "HIGH"),
    "SHA1": ("SHA-1", _D, _SSC, "HIGH"), "SHA1Managed": ("SHA-1", _D, _SSC, "HIGH"), "SHA1CryptoServiceProvider": ("SHA-1", _D, _SSC, "HIGH"), "SHA1Cng": ("SHA-1", _D, _SSC, "HIGH"),
    "SHA256": ("SHA-256", _D, _SSC, "HIGH"), "SHA256Managed": ("SHA-256", _D, _SSC, "HIGH"), "SHA256CryptoServiceProvider": ("SHA-256", _D, _SSC, "HIGH"), "SHA256Cng": ("SHA-256", _D, _SSC, "HIGH"),
    "SHA384": ("SHA-384", _D, _SSC, "HIGH"), "SHA384Managed": ("SHA-384", _D, _SSC, "HIGH"), "SHA384Cng": ("SHA-384", _D, _SSC, "HIGH"),
    "SHA512": ("SHA-512", _D, _SSC, "HIGH"), "SHA512Managed": ("SHA-512", _D, _SSC, "HIGH"), "SHA512Cng": ("SHA-512", _D, _SSC, "HIGH"),
    "SHA3_256": ("SHA3-256", _D, _SSC, "HIGH"), "SHA3_384": ("SHA3-384", _D, _SSC, "HIGH"), "SHA3_512": ("SHA3-512", _D, _SSC, "HIGH"), "Shake128": ("SHAKE128", _D, _SSC, "HIGH"), "Shake256": ("SHAKE256", _D, _SSC, "HIGH"),
    "HMACMD5": ("HMAC-MD5", _M, _SSC, "HIGH"), "HMACSHA1": ("HMAC-SHA1", _M, _SSC, "HIGH"), "HMACSHA256": ("HMAC-SHA256", _M, _SSC, "HIGH"), "HMACSHA384": ("HMAC-SHA384", _M, _SSC, "HIGH"), "HMACSHA512": ("HMAC-SHA512", _M, _SSC, "HIGH"),
    "HMACSHA3_256": ("HMAC-SHA3-256", _M, _SSC, "HIGH"), "MACTripleDES": ("3DES", _M, _SSC, "HIGH"), "HMACRIPEMD160": ("HMAC-RIPEMD160", _M, _SSC, "HIGH"), "RIPEMD160Managed": ("RIPEMD160", _D, _SSC, "HIGH"),
    "Rfc2898DeriveBytes": ("PBKDF2", _KDF, _SSC, "HIGH"), "PasswordDeriveBytes": ("PBKDF1", _KDF, _SSC, "HIGH"), "HKDF": ("HKDF", _KDF, _SSC, "HIGH"), "SP800108HmacCounterKdf": ("HMAC", _KDF, _SSC, "HIGH"),
    # BCL asymmetric / certs / RNG
    "RSA": ("RSA", _K, _SSC, "HIGH"), "RSACryptoServiceProvider": ("RSA", _K, _SSC, "HIGH"), "RSACng": ("RSA", _K, _SSC, "HIGH"), "RSAOpenSsl": ("RSA", _K, _SSC, "HIGH"), "RSAPKCS1SignatureFormatter": ("RSA", _S, _SSC, "HIGH"), "RSAOAEPKeyExchangeFormatter": ("RSA", _C, _SSC, "HIGH"), "RSAPKCS1KeyExchangeFormatter": ("RSA", _C, _SSC, "HIGH"),
    "DSA": ("DSA", _S, _SSC, "HIGH"), "DSACryptoServiceProvider": ("DSA", _S, _SSC, "HIGH"), "DSACng": ("DSA", _S, _SSC, "HIGH"),
    "ECDsa": ("ECDSA", _S, _SSC, "HIGH"), "ECDsaCng": ("ECDSA", _S, _SSC, "HIGH"), "ECDsaOpenSsl": ("ECDSA", _S, _SSC, "HIGH"),
    "ECDiffieHellman": ("ECDH", ("KEY_AGREEMENT", "KEY_EXCHANGE"), _SSC, "HIGH"), "ECDiffieHellmanCng": ("ECDH", ("KEY_AGREEMENT", "KEY_EXCHANGE"), _SSC, "HIGH"), "ECDiffieHellmanOpenSsl": ("ECDH", ("KEY_AGREEMENT", "KEY_EXCHANGE"), _SSC, "HIGH"),
    "MLKem": ("ML-KEM", _K, _SSC, "HIGH"), "MLDsa": ("ML-DSA", _S, _SSC, "HIGH"), "SlhDsa": ("SLH-DSA", _S, _SSC, "HIGH"),
    "RNGCryptoServiceProvider": ("CSPRNG", _KG, _SSC, "HIGH"), "RandomNumberGenerator": ("CSPRNG", _KG, _SSC, "HIGH"),
    "X509Certificate2": ("X509", _S, _SSC, "MEDIUM"), "X509Certificate": ("X509", _S, _SSC, "MEDIUM"), "X509Chain": ("X509", _S, _SSC, "MEDIUM"), "X509Store": ("X509", _S, _SSC, "MEDIUM"), "CertificateRequest": ("X509", _S, _SSC, "MEDIUM"),
    "SignedXml": ("XMLDSIG", _S, "System.Security.Cryptography.Xml", "MEDIUM"), "EncryptedXml": ("XMLENC", _C, "System.Security.Cryptography.Xml", "MEDIUM"), "SignedCms": ("CMS", _S, "System.Security.Cryptography.Pkcs", "MEDIUM"), "EnvelopedCms": ("CMS", _C, "System.Security.Cryptography.Pkcs", "MEDIUM"),
    "ProtectedData": ("DPAPI", _C, _SSC, "MEDIUM"), "ProtectedMemory": ("DPAPI", _C, _SSC, "MEDIUM"),
    "SslStream": ("TLS", _TLS, "System.Net.Security", "HIGH"), "SslClientAuthenticationOptions": ("TLS", _TLS, "System.Net.Security", "HIGH"), "SslServerAuthenticationOptions": ("TLS", _TLS, "System.Net.Security", "HIGH"),
    "ServicePointManager": ("TLS", _TLS, "System.Net", "MEDIUM"), "SecurityProtocolType": ("TLS", _TLS, "System.Net", "MEDIUM"), "SslProtocols": ("TLS", _TLS, "System.Security.Authentication", "MEDIUM"),
    "HttpClientHandler": ("TLS", _TLS, "System.Net.Http", "LOW"), "RemoteCertificateValidationCallback": ("X509", _TLS, "System.Net.Security", "MEDIUM"),
    # BouncyCastle
    "AesEngine": ("AES", _C, "Org.BouncyCastle", "HIGH"), "AesFastEngine": ("AES", _C, "Org.BouncyCastle", "HIGH"), "AesLightEngine": ("AES", _C, "Org.BouncyCastle", "HIGH"), "DesEngine": ("DES", _C, "Org.BouncyCastle", "HIGH"), "DesEdeEngine": ("3DES", _C, "Org.BouncyCastle", "HIGH"),
    "RC4Engine": ("RC4", _C, "Org.BouncyCastle", "HIGH"), "RC2Engine": ("RC2", _C, "Org.BouncyCastle", "HIGH"), "BlowfishEngine": ("Blowfish", _C, "Org.BouncyCastle", "HIGH"), "ChaCha7539Engine": ("ChaCha20", _C, "Org.BouncyCastle", "HIGH"), "ChaChaEngine": ("ChaCha20", _C, "Org.BouncyCastle", "HIGH"), "Salsa20Engine": ("Salsa20", _C, "Org.BouncyCastle", "HIGH"), "CamelliaEngine": ("Camellia", _C, "Org.BouncyCastle", "HIGH"), "SM4Engine": ("SM4", _C, "Org.BouncyCastle", "HIGH"), "RsaEngine": ("RSA", _C, "Org.BouncyCastle", "HIGH"), "RsaBlindedEngine": ("RSA", _C, "Org.BouncyCastle", "HIGH"),
    "Sha1Digest": ("SHA-1", _D, "Org.BouncyCastle", "HIGH"), "Sha256Digest": ("SHA-256", _D, "Org.BouncyCastle", "HIGH"), "Sha384Digest": ("SHA-384", _D, "Org.BouncyCastle", "HIGH"), "Sha512Digest": ("SHA-512", _D, "Org.BouncyCastle", "HIGH"), "Sha3Digest": ("SHA3", _D, "Org.BouncyCastle", "HIGH"), "MD5Digest": ("MD5", _D, "Org.BouncyCastle", "HIGH"), "MD4Digest": ("MD4", _D, "Org.BouncyCastle", "HIGH"), "RipeMD160Digest": ("RIPEMD160", _D, "Org.BouncyCastle", "HIGH"), "Blake2bDigest": ("BLAKE2b", _D, "Org.BouncyCastle", "HIGH"), "SM3Digest": ("SM3", _D, "Org.BouncyCastle", "HIGH"),
    "HMac": ("HMAC", _M, "Org.BouncyCastle", "HIGH"), "CMac": ("CMAC", _M, "Org.BouncyCastle", "HIGH"), "GMac": ("GMAC", _M, "Org.BouncyCastle", "HIGH"), "ISO9797Alg3Mac": ("3DES", _M, "Org.BouncyCastle", "HIGH"), "Poly1305": ("Poly1305", _M, "Org.BouncyCastle", "HIGH"),
    "Pkcs5S2ParametersGenerator": ("PBKDF2", _KDF, "Org.BouncyCastle", "HIGH"), "SCrypt": ("scrypt", _KDF, "Org.BouncyCastle", "HIGH"), "Argon2BytesGenerator": ("Argon2", _KDF, "Org.BouncyCastle", "HIGH"), "HkdfBytesGenerator": ("HKDF", _KDF, "Org.BouncyCastle", "HIGH"), "BCrypt": ("bcrypt", _KDF, "BCrypt.Net", "HIGH"), "OpenBsdBCrypt": ("bcrypt", _KDF, "Org.BouncyCastle", "HIGH"),
    "RsaKeyPairGenerator": ("RSA", _K, "Org.BouncyCastle", "HIGH"), "ECKeyPairGenerator": ("ECDSA", _K, "Org.BouncyCastle", "HIGH"), "ECDsaSigner": ("ECDSA", _S, "Org.BouncyCastle", "HIGH"), "RsaDigestSigner": ("RSA", _S, "Org.BouncyCastle", "HIGH"), "PssSigner": ("RSA-PSS", _S, "Org.BouncyCastle", "HIGH"), "Ed25519Signer": ("Ed25519", _S, "Org.BouncyCastle", "HIGH"), "Ed448Signer": ("Ed448", _S, "Org.BouncyCastle", "HIGH"), "X25519Agreement": ("X25519", ("KEY_AGREEMENT", "KEY_EXCHANGE"), "Org.BouncyCastle", "HIGH"), "ECDHBasicAgreement": ("ECDH", ("KEY_AGREEMENT", "KEY_EXCHANGE"), "Org.BouncyCastle", "HIGH"), "DHBasicAgreement": ("DH", ("KEY_AGREEMENT", "KEY_EXCHANGE"), "Org.BouncyCastle", "HIGH"), "GcmBlockCipher": ("AES", _C, "Org.BouncyCastle", "MEDIUM"), "CbcBlockCipher": ("UNKNOWN", _C, "Org.BouncyCastle", "LOW"),
    "KyberKeyPairGenerator": ("ML-KEM", _K, "Org.BouncyCastle", "HIGH"), "MLKemKeyPairGenerator": ("ML-KEM", _K, "Org.BouncyCastle", "HIGH"), "DilithiumSigner": ("ML-DSA", _S, "Org.BouncyCastle", "HIGH"), "MLDsaSigner": ("ML-DSA", _S, "Org.BouncyCastle", "HIGH"), "SphincsPlusSigner": ("SLH-DSA", _S, "Org.BouncyCastle", "HIGH"),
    "TlsClientProtocol": ("TLS", _TLS, "Org.BouncyCastle", "HIGH"), "TlsServerProtocol": ("TLS", _TLS, "Org.BouncyCastle", "HIGH"),
    # third-party
    "Argon2id": ("Argon2", _KDF, "Konscious", "HIGH"), "Argon2i": ("Argon2", _KDF, "Konscious", "HIGH"), "Argon2d": ("Argon2", _KDF, "Konscious", "HIGH"), "Argon2": ("Argon2", _KDF, ("Konscious", "Isopoh"), "HIGH"),
    "ScryptEncoder": ("scrypt", _KDF, "Scrypt", "HIGH"), "SecretBox": ("XSalsa20-Poly1305", _C, "Sodium", "HIGH"), "SecretAeadAes": ("AES", _C, "Sodium", "HIGH"), "PublicKeyBox": ("X25519", _C, "Sodium", "HIGH"), "PublicKeyAuth": ("Ed25519", _S, "Sodium", "HIGH"), "PasswordHash": ("Argon2", _KDF, "Sodium", "MEDIUM"), "GenericHash": ("BLAKE2b", _D, "Sodium", "HIGH"),
    "JwtSecurityTokenHandler": ("JWT", _S, "System.IdentityModel", "HIGH"), "JsonWebTokenHandler": ("JWT", _S, "Microsoft.IdentityModel", "HIGH"), "SigningCredentials": ("JWT", _S, "IdentityModel", "MEDIUM"), "SymmetricSecurityKey": ("HMAC", _S, "IdentityModel", "MEDIUM"), "RsaSecurityKey": ("RSA", _S, "IdentityModel", "MEDIUM"), "ECDsaSecurityKey": ("ECDSA", _S, "IdentityModel", "MEDIUM"),
    "JwtBuilder": ("JWT", _S, "JWT", "HIGH"), "HMACSHA256Algorithm": ("HS256", _S, "JWT", "HIGH"), "RS256Algorithm": ("RS256", _S, "JWT", "HIGH"), "ES256Algorithm": ("ES256", _S, "JWT", "HIGH"),
    "IDataProtector": ("AES", _C, "Microsoft.AspNetCore.DataProtection", "MEDIUM"), "KeyDerivation": ("PBKDF2", _KDF, "Microsoft.AspNetCore.Cryptography", "HIGH"),
    "Pkcs11InteropFactories": ("UNKNOWN", _K, "Net.Pkcs11Interop", "MEDIUM"), "Pkcs11Library": ("UNKNOWN", _K, "Net.Pkcs11Interop", "MEDIUM"),
    "CryptographyClient": ("UNKNOWN", _K, "Azure.Security.KeyVault", "MEDIUM"), "AmazonKeyManagementServiceClient": ("UNKNOWN", _K, "Amazon.KeyManagementService", "MEDIUM"), "KeyManagementServiceClient": ("UNKNOWN", _K, "Google.Cloud.Kms", "MEDIUM"),
    "SqlColumnEncryptionAzureKeyVaultProvider": ("AES", _C, "Microsoft.Data.SqlClient", "MEDIUM"),
    "SshClient": ("SSH", _TLS, "Renci.SshNet", "HIGH"), "SftpClient": ("SSH", _TLS, "Renci.SshNet", "HIGH"), "PrivateKeyFile": ("SSH", _K, "Renci.SshNet", "MEDIUM"),
    "MQEnvironment": ("TLS", _TLS, "IBM.WMQ", "LOW"),
}

# strings that name algorithms on their own (CryptoConfig / HashAlgorithmName / JWT alg / XML-DSig URIs)
_ALGO_LITERAL = re.compile(
    r"^(?:AES|Rijndael|TripleDES|3DES|DES|RC2|RC4|MD5|SHA1|SHA-1|SHA256|SHA-256|SHA384|SHA-384|SHA512|SHA-512|SHA3-256|SHA3-512|RSA|DSA|ECDSA|ECDsa|ECDH|HMACSHA1|HMACSHA256|HMACSHA384|HMACSHA512|HMACMD5|"
    r"System\.Security\.Cryptography\.(?:Aes|TripleDES|DES|RC2|MD5|SHA1|SHA256|SHA384|SHA512|RSA|DSA|ECDsa|HMACSHA\d+)\w*|"
    r"http://www\.w3\.org/200[019]/(?:04|09)/xml(?:enc|dsig)(?:-more)?#[a-z0-9-]+|"
    r"(?:HS|RS|PS|ES)(?:256|384|512)|EdDSA|none|"
    r"TLS|SSL|Tls|Tls11|Tls12|Tls13|Ssl3|Ssl2|"
    r"1\.2\.840\.113549\.\d+(?:\.\d+)*|1\.2\.840\.10045\.\d+(?:\.\d+)*|2\.16\.840\.1\.101\.3\.4\.\d+(?:\.\d+)*|1\.3\.101\.11[02])$"
)
_OIDS = {
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.113549.1.1.5": "SHA1withRSA", "1.2.840.113549.1.1.11": "SHA256withRSA", "1.2.840.113549.1.1.12": "SHA384withRSA", "1.2.840.113549.1.1.13": "SHA512withRSA", "1.2.840.113549.1.1.10": "RSA-PSS",
    "1.2.840.113549.2.5": "MD5", "1.3.14.3.2.26": "SHA-1", "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512",
    "2.16.840.1.101.3.4.1.2": "AES", "2.16.840.1.101.3.4.1.42": "AES", "2.16.840.1.101.3.4.1.6": "AES", "2.16.840.1.101.3.4.1.46": "AES", "1.2.840.113549.3.7": "3DES", "1.2.840.113549.3.2": "RC2", "1.2.840.113549.3.4": "RC4",
    "1.2.840.10045.2.1": "ECDSA", "1.2.840.10045.4.3.2": "SHA256withECDSA", "1.2.840.10045.4.3.3": "SHA384withECDSA", "1.3.101.110": "X25519", "1.3.101.112": "Ed25519", "1.2.840.113549.1.5.12": "PBKDF2", "1.2.840.113549.2.9": "HMAC-SHA256",
}
_XMLURI = {
    "aes128-cbc": "AES", "aes192-cbc": "AES", "aes256-cbc": "AES", "aes128-gcm": "AES", "aes256-gcm": "AES", "tripledes-cbc": "3DES", "kw-aes128": "AES", "kw-aes256": "AES", "kw-tripledes": "3DES",
    "rsa-1_5": "RSA", "rsa-oaep": "RSA", "rsa-oaep-mgf1p": "RSA", "rsa-sha1": "SHA1withRSA", "rsa-sha256": "SHA256withRSA", "rsa-sha384": "SHA384withRSA", "rsa-sha512": "SHA512withRSA", "dsa-sha1": "DSA", "ecdsa-sha256": "SHA256withECDSA", "hmac-sha1": "HMAC-SHA1", "hmac-sha256": "HMAC-SHA256",
    "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5", "ripemd160": "RIPEMD160",
}
_TLS_LITERAL = {"TLS": "TLS", "SSL": "TLS", "Tls": "TLS1.0", "Tls11": "TLS1.1", "Tls12": "TLS1.2", "Tls13": "TLS1.3", "Ssl3": "SSLv3", "Ssl2": "SSLv2"}
_JWT_ALG = re.compile(r"^(?:HS|RS|PS|ES)(?:256|384|512)$|^EdDSA$|^none$")
_TRANSFORM = re.compile(r"^(?:AES|DES|DESede|TripleDES|RSA|Blowfish|RC2|RC4|ChaCha20)(?:/[A-Za-z0-9_]+){1,2}$")

# ----------------------------------------------------------------------------- native imports

_IMPORTS: tuple[tuple[re.Pattern, str, tuple[str, str], str, str], ...] = (
    (re.compile(r"^BCrypt(?:Encrypt|Decrypt|OpenAlgorithmProvider|GenerateSymmetricKey|ImportKeyPair|SignHash|VerifySignature|SecretAgreement|DeriveKey\w*|GenRandom|CreateHash|HashData|KeyDerivation)$"), "UNKNOWN", _C, "Windows-CNG", "MEDIUM"),
    (re.compile(r"^NCrypt(?:Encrypt|Decrypt|SignHash|VerifySignature|OpenStorageProvider|OpenKey|CreatePersistedKey|SecretAgreement|DeriveKey|ExportKey|ImportKey)$"), "UNKNOWN", _K, "Windows-CNG-KSP", "MEDIUM"),
    (re.compile(r"^Crypt(?:AcquireContext[AW]|Encrypt|Decrypt|CreateHash|HashData|GenKey|DeriveKey|ImportKey|ExportKey|SignHash[AW]|VerifySignature[AW]|GenRandom)$"), "UNKNOWN", _C, "Windows-CryptoAPI", "MEDIUM"),
    (re.compile(r"^CryptProtectData$|^CryptUnprotectData$|^CryptProtectMemory$"), "DPAPI", _C, "Windows-DPAPI", "HIGH"),
    (re.compile(r"^(?:AcquireCredentialsHandle[AW]|InitializeSecurityContext[AW]|AcceptSecurityContext|EncryptMessage|DecryptMessage|SslEmptyCache[AW]?)$"), "TLS", _TLS, "Schannel/SSPI", "MEDIUM"),
    (re.compile(r"^Cert(?:OpenStore|FindCertificateInStore|GetCertificateChain|VerifyCertificateChainPolicy|CreateCertificateContext|OpenSystemStore[AW])$|^PFXImportCertStore$"), "X509", _S, "Windows-CryptoAPI", "MEDIUM"),
    (re.compile(r"^EVP_aes_(?:128|192|256)_\w+$"), "AES", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_des_ede3?\w*$|^DES_(?:ede3_cbc_encrypt|ncbc_encrypt|set_key\w*)$"), "3DES", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_des_(?:cbc|ecb|cfb\w*|ofb)$|^DES_ecb_encrypt$"), "DES", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_rc4\w*$|^RC4(?:_set_key)?$"), "RC4", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_rc2_\w+$"), "RC2", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_bf_\w+$"), "Blowfish", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_chacha20(?:_poly1305)?$"), "ChaCha20", _C, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_md5$|^MD5(?:_Init|_Update|_Final)?$"), "MD5", _D, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_sha1$|^SHA1(?:_Init|_Update|_Final)?$"), "SHA-1", _D, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_sha256$|^SHA256(?:_Init|_Update|_Final)?$"), "SHA-256", _D, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_sha384$|^SHA384(?:_Init|_Update|_Final)?$"), "SHA-384", _D, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_sha512$|^SHA512(?:_Init|_Update|_Final)?$"), "SHA-512", _D, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_sha3_\d+$"), "SHA3", _D, "OpenSSL", "HIGH"),
    (re.compile(r"^HMAC(?:_Init_ex|_Update|_Final|_CTX_new)?$"), "HMAC", _M, "OpenSSL", "HIGH"),
    (re.compile(r"^PKCS5_PBKDF2_HMAC(?:_SHA1)?$"), "PBKDF2", _KDF, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_PBE_scrypt$"), "scrypt", _KDF, "OpenSSL", "HIGH"),
    (re.compile(r"^RSA_(?:new|generate_key\w*|public_encrypt|private_decrypt|sign|verify|size)$|^EVP_PKEY_(?:encrypt|decrypt)$"), "RSA", _K, "OpenSSL", "HIGH"),
    (re.compile(r"^EC_KEY_(?:new\w*|generate_key)$|^ECDSA_(?:sign|verify|do_sign|do_verify)$"), "ECDSA", _S, "OpenSSL", "HIGH"),
    (re.compile(r"^ECDH_compute_key$|^EVP_PKEY_derive$"), "ECDH", ("KEY_AGREEMENT", "KEY_EXCHANGE"), "OpenSSL", "MEDIUM"),
    (re.compile(r"^RAND_(?:bytes|priv_bytes|seed|poll)$"), "CSPRNG", _KG, "OpenSSL", "HIGH"),
    (re.compile(r"^EVP_(?:Encrypt|Decrypt|Cipher)(?:Init(?:_ex)?|Update|Final(?:_ex)?)$|^EVP_CIPHER_fetch$"), "UNKNOWN", _C, "OpenSSL", "MEDIUM"),
    (re.compile(r"^EVP_Digest(?:Init(?:_ex)?|Update|Final(?:_ex)?|Sign\w*|Verify\w*)$|^EVP_MD_fetch$"), "UNKNOWN", _D, "OpenSSL", "MEDIUM"),
    (re.compile(r"^SSL_(?:CTX_new|new|connect|accept|read|write|CTX_set_cipher_list|CTX_set_ciphersuites|CTX_set_min_proto_version|CTX_set_verify|set_verify)$|^TLS_(?:client|server)?_?method$|^TLSv1_[0-3]?_?(?:client_|server_)?method$|^SSLv23_(?:client_|server_)?method$|^SSLv3_(?:client_|server_)?method$"), "TLS", _TLS, "OpenSSL", "HIGH"),
    (re.compile(r"^crypto_secretbox_\w+$"), "XSalsa20-Poly1305", _C, "libsodium", "HIGH"),
    (re.compile(r"^crypto_aead_xchacha20poly1305\w*$|^crypto_aead_chacha20poly1305\w*$"), "ChaCha20-Poly1305", _C, "libsodium", "HIGH"),
    (re.compile(r"^crypto_aead_aes256gcm\w*$"), "AES", _C, "libsodium", "HIGH"),
    (re.compile(r"^crypto_box_\w+$"), "X25519", _C, "libsodium", "HIGH"),
    (re.compile(r"^crypto_sign_\w+$"), "Ed25519", _S, "libsodium", "HIGH"),
    (re.compile(r"^crypto_pwhash\w*$"), "Argon2", _KDF, "libsodium", "HIGH"),
    (re.compile(r"^crypto_generichash\w*$"), "BLAKE2b", _D, "libsodium", "HIGH"),
    (re.compile(r"^randombytes_buf$"), "CSPRNG", _KG, "libsodium", "HIGH"),
    (re.compile(r"^mbedtls_aes_\w+$"), "AES", _C, "mbedTLS", "HIGH"),
    (re.compile(r"^mbedtls_des3?_\w+$"), "3DES", _C, "mbedTLS", "MEDIUM"),
    (re.compile(r"^mbedtls_(?:sha256|sha512|sha1|md5)\w*$"), "UNKNOWN", _D, "mbedTLS", "MEDIUM"),
    (re.compile(r"^mbedtls_(?:ssl_setup|ssl_handshake|ssl_config_defaults)$"), "TLS", _TLS, "mbedTLS", "HIGH"),
    (re.compile(r"^mbedtls_rsa_\w+$"), "RSA", _K, "mbedTLS", "HIGH"),
    (re.compile(r"^mbedtls_ecdsa_\w+$"), "ECDSA", _S, "mbedTLS", "HIGH"),
    (re.compile(r"^wolfSSL_(?:CTX_new|new|connect|accept)$|^wc_Aes\w+$"), "TLS", _TLS, "wolfSSL", "HIGH"),
    (re.compile(r"^wc_(?:Sha256|Sha512|Sha|Md5)\w*$"), "UNKNOWN", _D, "wolfSSL", "MEDIUM"),
    (re.compile(r"^C_(?:Initialize|OpenSession|Login|Encrypt|Decrypt|Sign|Verify|GenerateKey|GenerateKeyPair|WrapKey|UnwrapKey|DeriveKey|Digest)$"), "UNKNOWN", _K, "PKCS#11", "HIGH"),
    (re.compile(r"^(?:SystemFunction036|RtlGenRandom)$"), "CSPRNG", _KG, "Windows", "HIGH"),
)
_MBED_DIGEST = {"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5", "Sha256": "SHA-256", "Sha512": "SHA-512", "Sha": "SHA-1", "Md5": "MD5"}

# ----------------------------------------------------------------------------- analysis


def _finding(rel: str, member: str, algo: str, api: str, purpose: str, lib: str, evidence: str, conf: str, artifact: str, language: str) -> RawFinding:
    algo = known_algorithm_or_unknown(algo) if algo and algo != "UNKNOWN" else algo
    return RawFinding(
        scanner_id=SCANNER_ID,
        source=SourceLocation(type="BINARY", language=language, file_path=f"{rel}!{member}", line_number=0, code_snippet=evidence[:120]),
        crypto=CryptoInfo(api_type=api, algorithm=algo, raw_transformation=evidence[:120]),
        metadata=FindingMetadata(confidence=conf, confidence_reason=f"{'.NET metadata' if language == 'CSHARP' else 'PE import table'} of {artifact}", library=lib, code_origin="archive"),
    )


def analyse_dotnet(strings: list[str], user: list[str]) -> list[tuple[str, str, str, str, str, str, str]]:
    """→ (member, algorithm, api_type, purpose, library, evidence, confidence)."""
    sset = set(strings)
    namespaces = {ns for ns in _NAMESPACES if ns in sset}
    out: list[tuple[str, str, str, str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def put(member: str, algo: str, api: tuple[str, str], lib: str, evidence: str, conf: str) -> None:
        key = (member, algo)
        if key in seen:
            return
        seen.add(key)
        out.append((member, algo, api[0], api[1], lib, evidence, conf))

    for tname, (algo, api, ns_req, conf) in _TYPES.items():
        if tname not in sset:
            continue
        reqs = ns_req if isinstance(ns_req, tuple) else (ns_req,)
        matched_ns = next((ns for ns in namespaces for r in reqs if r and ns.startswith(r)), None)
        if matched_ns is None:
            continue  # namespace gate: the identifier alone is not evidence
        put(tname, algo, api, _NAMESPACES[matched_ns], f"type reference {tname}", conf)

    # namespace-only evidence for libraries whose type names are generic
    for ns, lib in ((n, _NAMESPACES[n]) for n in namespaces):
        if ns in ("Konscious.Security.Cryptography", "Isopoh.Cryptography.Argon2"):
            put(ns, "Argon2", _KDF, lib, f"namespace {ns}", "HIGH")
        elif ns == "BCrypt.Net":
            put(ns, "bcrypt", _KDF, lib, f"namespace {ns}", "HIGH")
        elif ns in ("Net.Pkcs11Interop", "Net.Pkcs11Interop.HighLevelAPI"):
            put(ns, "UNKNOWN", _K, lib, f"namespace {ns}", "MEDIUM")
        elif ns in ("Thales.Luna", "SafeNet.Luna", "nCipher", "Utimaco", "PaymentHSM", "Thales.PayShield"):
            put(ns, "UNKNOWN", _K, lib, f"namespace {ns}", "MEDIUM")
        elif ns.startswith("Org.BouncyCastle.Pqc"):
            put(ns, "UNKNOWN", _K, lib, f"namespace {ns}", "MEDIUM")

    for lit in user:
        s = lit.strip()
        if not s or len(s) > 200 or not _ALGO_LITERAL.match(s):
            if _TRANSFORM.match(s):
                parsed = parse_transformation(s)
                put(f"string:{s}", parsed.algorithm or "UNKNOWN", _C, "string-literal", s, "MEDIUM")
            continue
        if s.startswith("http://www.w3.org/"):
            algo = _XMLURI.get(s.rsplit("#", 1)[-1])
            if algo:
                put(f"string:{s}", algo, _S if "dsig" in s else _C, "xml-security", s, "HIGH")
            continue
        if s[0].isdigit():
            algo = _OIDS.get(s)
            if algo:
                put(f"string:{s}", algo, _K, "oid", s, "HIGH")
            continue
        if not namespaces:
            continue  # a bare "AES"/"SHA256" literal in an assembly with no crypto namespace is a label, not usage
        if _JWT_ALG.match(s):
            put(f"string:{s}", s if s != "none" else "JWT-NONE", _S, "jwt", s, "HIGH")
            continue
        if s in _TLS_LITERAL:
            put(f"string:{s}", _TLS_LITERAL[s], _TLS, "tls", s, "MEDIUM")
            continue
        name = s.rsplit(".", 1)[-1]
        if name in _TYPES:
            algo, api, _, _ = _TYPES[name]
            put(f"string:{s}", algo, api, "CryptoConfig", s, "HIGH")
        elif name in ("3DES", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512", "ECDH"):
            put(f"string:{s}", name, _D if name.upper().startswith(("SHA", "MD5")) else _C, "algorithm-name", s, "MEDIUM")
    return out


def analyse_imports(imports: list[tuple[str, str]]) -> list[tuple[str, str, str, str, str, str, str]]:
    out = []
    seen: set[tuple[str, str]] = set()
    for dll, sym in imports:
        for rx, algo, api, lib, conf in _IMPORTS:
            if rx.match(sym):
                if algo == "UNKNOWN" and lib in ("mbedTLS", "wolfSSL"):
                    for k, v in _MBED_DIGEST.items():
                        if k in sym:
                            algo = v
                            break
                key = (sym, algo)
                if key not in seen:
                    seen.add(key)
                    out.append((f"import:{sym}", algo, api[0], api[1], lib, f"{dll} → {sym}", conf))
                break
    return out


def scan_assembly(path: Path | str, repo_root: Path | str | None = None) -> list[RawFinding]:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return []
    return scan_assembly_bytes(data, _rel(p, repo_root))


def scan_assembly_bytes(data: bytes, rel: str) -> list[RawFinding]:
    try:
        pe = _PE(data)
    except (ValueError, struct.error, IndexError):
        return []
    artifact = rel.rsplit("/", 1)[-1]
    out: list[RawFinding] = []
    try:
        heaps = pe.dotnet_heaps()
    except (struct.error, IndexError, ValueError):
        heaps = None
    if heaps:
        for member, algo, api, purpose, lib, evidence, conf in analyse_dotnet(*heaps):
            out.append(_finding(rel, member, algo, api, purpose, lib, evidence, conf, artifact, "CSHARP"))
    try:
        imps = pe.imports()
    except (struct.error, IndexError, ValueError):
        imps = []
    for member, algo, api, purpose, lib, evidence, conf in analyse_imports(imps):
        out.append(_finding(rel, member, algo, api, purpose, lib, evidence, conf, artifact, "C"))
    return out


def _rel(p: Path, repo_root: Path | str | None) -> str:
    if repo_root:
        try:
            return p.resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except ValueError:
            pass
    return p.as_posix()

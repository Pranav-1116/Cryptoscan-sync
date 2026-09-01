"""§9 Runtime crypto detection + §27 capability vs usage.

Runtime observation answers: *is this cryptographic capability actually being
exercised?* — much stronger than static detection. The runtime engine takes a
process snapshot (loaded libraries, observed crypto API calls, network
connections with TLS/SSH/IPsec metadata) and emits observations flagged
``usage=True``.

§27 keeps two separate datasets:
  CRYPTO_CAPABILITY — what the hardware/implementation supports
  CRYPTO_USAGE      — what is actually exercised at runtime
"Server supports AES-NI" and "HSM supports ML-KEM" are capabilities, never
usage. The engine never conflates the two.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

#: observed crypto API → algorithm (runtime catalog, same deterministic shape)
_RUNTIME_API_ALGORITHMS: dict[str, str] = {
    "EVP_DigestUpdate": "SHA-256", "EVP_EncryptUpdate": "AES",
    "EVP_DecryptUpdate": "AES", "EVP_DigestSign": "RSA",
    "EVP_DigestVerify": "RSA", "SSL_do_handshake": "TLS",
    "RSA_sign": "RSA", "ECDSA_sign": "ECDSA", "RAND_bytes": "CSPRNG",
    "CryptEncrypt": "RSA", "BCryptEncrypt": "AES",
    "MessageDigest.digest": "SHA-256", "Cipher.doFinal": "AES",
    "Signature.sign": "RSA", "KeyAgreement.generateSecret": "ECDH",
    "crypto.subtle.encrypt": "AES-GCM", "crypto.subtle.sign": "ECDSA",
    "tls.connect": "TLS", "crypto.createHash": "SHA-256",
    "sha256::digest": "SHA-256", "ring::signature::sign": "RSA",
}

#: loaded crypto library name → canonical library
_LOADED_LIBRARY: dict[str, str] = {
    "libssl.so": "OpenSSL", "libcrypto.so": "OpenSSL", "ssl": "OpenSSL",
    "libmbedtls.so": "mbedTLS", "libsodium.so": "libsodium",
    "libbotan-2.so": "Botan", "libwolfssl.so": "wolfSSL",
    "bcprov-jdk18on": "BouncyCastle", "System.Security.Cryptography": ".NET cryptography",
    "libcryptopp.so": "Crypto++",
}


class RuntimeObservation:
    """One runtime crypto observation (usage = exercised, §9/§27)."""

    def __init__(
        self,
        *,
        process: str,
        algorithm: str,
        api: str = "",
        library: Optional[str] = None,
        connection: Optional[str] = None,
        protocol: Optional[str] = None,
        asset_id: str = "default",
        usage: bool = True,
    ) -> None:
        self.process = process
        self.algorithm = algorithm
        self.api = api
        self.library = library
        self.connection = connection
        self.protocol = protocol
        self.asset_id = asset_id
        self.usage = usage

    def to_dict(self) -> dict[str, Any]:
        return {
            "process": self.process,
            "algorithm": self.algorithm,
            "api": self.api,
            "library": self.library,
            "connection": self.connection,
            "protocol": self.protocol,
            "asset_id": self.asset_id,
            "usage": self.usage,
        }


class RuntimeCryptoEngine:
    """§9 runtime crypto observation from process snapshots."""

    def __init__(self) -> None:
        self.observations: list[RuntimeObservation] = []

    def observe(
        self,
        *,
        process: str,
        loaded_libraries: Optional[Iterable[str]] = None,
        api_calls: Optional[Iterable[str]] = None,
        connections: Optional[Iterable[dict[str, Any]]] = None,
        asset_id: str = "default",
    ) -> list[RuntimeObservation]:
        """Turn a process snapshot into runtime crypto observations."""
        out: list[RuntimeObservation] = []
        for lib in loaded_libraries or []:
            canonical = _LOADED_LIBRARY.get(lib)
            if canonical:
                out.append(RuntimeObservation(
                    process=process, algorithm=canonical, api="", library=canonical,
                    asset_id=asset_id, usage=False))  # loaded ≠ exercised (§27)
        seen: set[tuple[str, str]] = set()
        for call in api_calls or []:
            alg = _RUNTIME_API_ALGORITHMS.get(call)
            if alg and (alg, call) not in seen:
                seen.add((alg, call))
                out.append(RuntimeObservation(
                    process=process, algorithm=alg, api=call,
                    library=_library_for_call(call), asset_id=asset_id, usage=True))
        for conn in connections or []:
            protocol = conn.get("protocol")
            if protocol in ("TLS", "SSH", "IPsec", "QUIC"):
                out.append(RuntimeObservation(
                    process=process, algorithm=protocol, api="",
                    library=conn.get("library"), connection=conn.get("peer"),
                    protocol=protocol, asset_id=asset_id, usage=True))
        self.observations.extend(out)
        return out

    # -- §27 capability vs usage ------------------------------------------

    def capability_vs_usage(
        self,
        *,
        capabilities: Iterable[dict[str, Any]],
        usage: Iterable[RuntimeObservation],
    ) -> dict[str, Any]:
        """Two separate datasets; the split is explicit and never conflated.

        ``capabilities``: [{algorithm, hardware (e.g. "AES-NI" / "HSM"),
        supported: bool}] — vendor/device capability declarations.
        ``usage``: runtime observations (exercised APIs/connections).
        """
        cap: dict[str, dict[str, Any]] = {}
        for item in capabilities:
            alg = item.get("algorithm", "")
            if not alg:
                continue
            cap[alg] = {
                "algorithm": alg,
                "hardware": item.get("hardware", ""),
                "supported": bool(item.get("supported", True)),
                "usage": False,
                "exercised_by": [],
            }
        for obs in usage:
            if not obs.usage:
                continue
            entry = cap.setdefault(obs.algorithm, {
                "algorithm": obs.algorithm,
                "hardware": "",
                "supported": False,
                "usage": True,
                "exercised_by": [],
            })
            entry["usage"] = True
            if obs.process not in entry["exercised_by"]:
                entry["exercised_by"].append(obs.process)
        return {
            "capabilities": cap,
            "supported_but_unused": [
                a for a, e in cap.items() if e["supported"] and not e["usage"]
            ],
            "used_without_declared_capability": [
                a for a, e in cap.items() if e["usage"] and not e["supported"]
            ],
        }


def _library_for_call(call: str) -> str:
    if call.startswith(("EVP_", "RSA_", "ECDSA_", "RAND_", "SSL_")):
        return "OpenSSL"
    if call.startswith(("Crypt", "BCrypt")):
        return "Windows CNG"
    if call.startswith(("MessageDigest", "Cipher", "Signature", "KeyAgreement")):
        return "JCA-JCE"
    if call.startswith("crypto."):
        return "Node crypto / WebCrypto"
    if call.startswith(("sha256", "ring::")):
        return "RustCrypto"
    return ""

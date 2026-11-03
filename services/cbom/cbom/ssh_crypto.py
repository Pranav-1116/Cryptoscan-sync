"""SSH is a negotiation too, and it negotiates four things per direction.

Review item 13 asks for SSH depth. The reason SSH needs its own model is that it is not
one cipher suite but **four independent negotiations**, and two of them run in **each
direction separately**:

    key exchange · host key · cipher (client→server, server→client)
                · MAC (client→server, server→client)

A host can therefore encrypt in one direction with `chacha20-poly1305` and the other
with `aes128-cbc`, and an inventory that records "SSH, AES-128" as a single value is
wrong in a way that matters: the weak direction is the one an attacker uses.

Two more things are specific to SSH and are modelled here rather than borrowed from TLS:

* **`ssh-rsa` is the SHA-1 signature algorithm**, not "RSA". A server offering an RSA host
  key with `rsa-sha2-256` is fine; one that offers `ssh-rsa` is using SHA-1 to sign the
  exchange. The two look identical if you only read the key type, which is why the
  signature algorithm is its own field.
* **the client's preference decides.** SSH negotiates the first algorithm on the *client*
  list that the server also supports, so "server supported algorithms" and "algorithm
  used" are different answers — exactly the SUPPORTED/CONFIGURED/NEGOTIATED distinction
  guide 154 keeps for TLS.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.cbom-ssh/1"

#: the four negotiations, in the order RFC 4253 defines them
DIMENSIONS: tuple[str, ...] = ("KEX", "HOST_KEY", "CIPHER", "MAC")

#: SSH negotiates two of the four per direction
DIRECTIONS: tuple[str, ...] = ("CLIENT_TO_SERVER", "SERVER_TO_CLIENT")

EVIDENCE: tuple[str, ...] = ("NEGOTIATED", "SUPPORTED", "CONFIGURED")

#: algorithms that must not be offered, and why
DEPRECATED: dict[str, str] = {
    "diffie-hellman-group1-sha1": "1024-bit Oakley group 2 with SHA-1",
    "diffie-hellman-group14-sha1": "SHA-1 in the key exchange hash",
    "ssh-dss": "DSA keys are limited to 1024 bits and are forbidden by RFC 8332",
    "ssh-rsa": "SHA-1 signatures; rsa-sha2-256/512 supersede it",
    "3des-cbc": "64-bit block cipher with a sweet32 birthday bound",
    "des-cbc": "56-bit key",
    "arcfour": "RC4",
    "arcfour128": "RC4",
    "arcfour256": "RC4",
    "hmac-md5": "MD5 MAC",
    "hmac-md5-96": "MD5 MAC",
    "hmac-sha1-96": "truncated SHA-1 MAC",
    "none": "no MAC at all",
    "aes128-cbc": "CBC mode with no authenticated encryption",
    "aes192-cbc": "CBC mode with no authenticated encryption",
    "aes256-cbc": "CBC mode with no authenticated encryption",
    "rijndael-cbc@lysator.liu.se": "CBC mode with no authenticated encryption",
}

#: algorithms whose security rests on a problem a quantum computer breaks
QUANTUM_VULNERABLE: dict[str, str] = {
    "curve25519-sha256": "X25519 key agreement",
    "curve25519-sha256@libssh.org": "X25519 key agreement",
    "ecdh-sha2-nistp256": "ECDH P-256",
    "ecdh-sha2-nistp384": "ECDH P-384",
    "ecdh-sha2-nistp521": "ECDH P-521",
    "diffie-hellman-group14-sha256": "finite-field DH",
    "diffie-hellman-group16-sha512": "finite-field DH",
    "diffie-hellman-group18-sha512": "finite-field DH",
    "diffie-hellman-group-exchange-sha256": "finite-field DH",
    "ssh-rsa": "RSA host key",
    "rsa-sha2-256": "RSA host key",
    "rsa-sha2-512": "RSA host key",
    "ecdsa-sha2-nistp256": "ECDSA host key",
    "ecdsa-sha2-nistp384": "ECDSA host key",
    "ssh-ed25519": "Ed25519 host key",
    "ssh-dss": "DSA host key",
}

#: MACs that also authenticate the ciphertext are AEAD and need no separate MAC
AEAD_CIPHERS: tuple[str, ...] = ("chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
                                 "aes256-gcm@openssh.com")

#: key sizes implied by a name, for the report rather than the verdict
CIPHER_BITS: dict[str, int] = {
    "aes128": 128, "aes192": 192, "aes256": 256, "3des": 168, "des": 56,
    "chacha20-poly1305": 256,
}

NOT_PROVEN = [
    "that the algorithm used is the only one the server accepts: one session is one "
    "negotiation, and the server's full offer is a different question",
    "that a client chose the strongest algorithm it supports: SSH takes the first "
    "client preference the server also offers, so a weak client choice can be used "
    "against a strong server",
    "that a key is trustworthy: the host key is identified by its fingerprint and "
    "trusted by the client's known_hosts, neither of which this model reads",
    "that a session was not tunnelled: an SSH connection can forward ports, and the "
    "cryptography of what it forwards is somebody else's negotiation",
]

#: SSH banner versions are not cryptography and are recorded, never judged
DEFAULT_PORTS = {"22", "2222"}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _names(value: Any) -> list[str]:
    """An algorithm list, from a comma string, a list, or a single name."""
    if value is None:
        return []
    if isinstance(value, str):
        return [token.strip().lower() for token in value.split(",") if token.strip()]
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return [str(token).strip().lower() for token in value if str(token).strip()]
    return []


def _bits(algorithm: str) -> int | None:
    for token, size in CIPHER_BITS.items():
        if token in algorithm:
            return size
    return None


def algorithm(name: str, dimension: str) -> dict[str, Any]:
    """One SSH algorithm, judged in the dimension it belongs to."""
    token = (name or "").strip().lower()
    if not token:
        raise ValueError("an SSH algorithm needs a name")
    deprecated = DEPRECATED.get(token)
    quantum = QUANTUM_VULNERABLE.get(token)
    aead = token in AEAD_CIPHERS
    bits = _bits(token) if dimension == "CIPHER" else None
    if dimension not in DIMENSIONS:
        raise ValueError(f"{dimension} is not one of {', '.join(DIMENSIONS)}")
    if deprecated:
        rating = ("BROKEN" if any(marker in token for marker in
                                  ("arcfour", "md5", "des-cbc", "group1", "none"))
                  else "DEPRECATED")
    elif dimension == "CIPHER" and bits is not None and bits < 128:
        rating = "DEPRECATED"
    elif dimension == "HOST_KEY" and token == "ssh-rsa":
        rating = "DEPRECATED"
    else:
        rating = "ACCEPTABLE"
    return {
        "algorithm": token,
        "dimension": dimension,
        "rating": rating,
        "reason": deprecated,
        "key_bits": bits,
        "aead": aead,
        "quantum_vulnerable": quantum,
        "quantum_note": quantum,
    }


def session(row: Mapping[str, Any]) -> dict[str, Any]:
    """One SSH session record → both directions, and every refusal it deserves."""
    if not isinstance(row, Mapping):
        raise ValueError("an SSH session must be an object")
    host = _text(row.get("host") or row.get("endpoint"))
    if not host:
        raise ValueError("an SSH session needs a host")
    evidence = _text(row.get("evidence_id"))
    if not evidence:
        raise ValueError(
            f"{host}: an SSH session with no evidence id is a claim, not an observation")
    negotiated = row.get("negotiated") if isinstance(row.get("negotiated"), Mapping) else {}
    supported = row.get("server_supported") if isinstance(
        row.get("server_supported"), Mapping) else {}

    directions: dict[str, Any] = {}
    for direction in DIRECTIONS:
        cipher_name = _text(negotiated.get(f"cipher_{direction.lower()}")
                            or negotiated.get(
                                "cipher" if direction == "CLIENT_TO_SERVER"
                                else "cipher_s2c"))
        mac_name = _text(negotiated.get(f"mac_{direction.lower()}")
                         or negotiated.get("mac" if direction == "CLIENT_TO_SERVER"
                                           else "mac_s2c"))
        cipher = algorithm(cipher_name, "CIPHER") if cipher_name else None
        mac = algorithm(mac_name, "MAC") if mac_name else None
        if cipher and cipher["aead"]:
            mac = None  # an AEAD cipher authenticates; a separate MAC is not negotiated
        directions[direction] = {"cipher": cipher, "mac": mac,
                                 "evidence": "NEGOTIATED" if cipher or mac else "UNKNOWN"}

    kex_name = _text(negotiated.get("kex"))
    host_key_name = _text(negotiated.get("host_key"))
    base = {
        "host": host,
        "port": row.get("port") or 22,
        "banner": _text(row.get("banner")),
        "kex": algorithm(kex_name, "KEX") if kex_name else None,
        "host_key": algorithm(host_key_name, "HOST_KEY") if host_key_name else None,
        "directions": directions,
        "asymmetric": bool(directions["CLIENT_TO_SERVER"]["cipher"]
                           and directions["SERVER_TO_CLIENT"]["cipher"]
                           and directions["CLIENT_TO_SERVER"]["cipher"]["algorithm"]
                           != directions["SERVER_TO_CLIENT"]["cipher"]["algorithm"]),
        "host_key_fingerprint": _text(row.get("host_key_fingerprint")),
        "server_supported": {name: _names(supported.get(name)) for name in
                             ("kex", "host_key", "cipher", "mac")},
        "client_preference": {name: _names((row.get("client_preference") or {}).get(name))
                              for name in DIMENSIONS}
        if isinstance(row.get("client_preference"), Mapping) else {},
        "evidence_ids": [evidence],
        "source": _text(row.get("source")),
        "observed_at": _text(row.get("observed_at")),
        "state": "NEGOTIATED",
        "private_material": "NOT_STORED",
    }
    problems: list[dict[str, Any]] = []
    for label, row_algorithm in (("KEX", base["kex"]), ("HOST_KEY", base["host_key"])):
        if row_algorithm and row_algorithm["rating"] != "ACCEPTABLE":
            problems.append({"dimension": label,
                             "algorithm": row_algorithm["algorithm"],
                             "rating": row_algorithm["rating"],
                             "detail": row_algorithm["reason"]})
    for direction, rows in directions.items():
        for label in ("cipher", "mac"):
            row_algorithm = rows[label]
            if row_algorithm and row_algorithm["rating"] != "ACCEPTABLE":
                problems.append({"dimension": label.upper(), "direction": direction,
                                 "algorithm": row_algorithm["algorithm"],
                                 "rating": row_algorithm["rating"],
                                 "detail": row_algorithm["reason"]})
    base["problems"] = problems
    base["statement"] = _statement(base)
    return base


def _statement(body: Mapping[str, Any]) -> str:
    kex = (body.get("kex") or {}).get("algorithm") or "unknown kex"
    host_key = (body.get("host_key") or {}).get("algorithm") or "unknown host key"
    c2s = (body["directions"]["CLIENT_TO_SERVER"]["cipher"] or {}).get("algorithm")
    s2c = (body["directions"]["SERVER_TO_CLIENT"]["cipher"] or {}).get("algorithm")
    return (f"{body['host']}:{body['port']} negotiated {kex} · {host_key} · "
            f"{c2s or 'unknown cipher'} (c→s) · {s2c or 'unknown cipher'} (s→c)"
            + ("; the two directions use different ciphers, so the weaker one decides"
               if body["asymmetric"] else "")
            + f"; {len(body['problems'])} deprecated algorithm(s)"
            if body["problems"] else
            f"{body['host']}:{body['port']} negotiated {kex} · {host_key} · "
            f"{c2s or 'unknown cipher'} (c→s) · {s2c or 'unknown cipher'} (s→c)"
            + ("; the two directions use different ciphers, so the weaker one decides"
               if body["asymmetric"] else "") + "; no deprecated algorithm in this session")


def estate(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Many sessions → what the SSH surface looks like, and what was refused."""
    sessions: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in rows or ():
        try:
            sessions.append(session(row))
        except ValueError as exc:
            refused.append({"session": row if not isinstance(row, Mapping) else
                            {key: row.get(key) for key in ("host", "endpoint", "port")},
                            "reason": str(exc)})
    deprecated: dict[str, list[str]] = {}
    for body in sessions:
        for problem in body["problems"]:
            deprecated.setdefault(problem["algorithm"], []).append(body["host"])
    hosts = sorted({body["host"] for body in sessions})
    asymmetric = sorted({body["host"] for body in sessions if body["asymmetric"]})
    return {
        "schema": SCHEMA,
        "sessions": sessions,
        "hosts": hosts,
        "refused": refused,
        "deprecated": {name: sorted(set(value)) for name, value in deprecated.items()},
        "asymmetric_directions": asymmetric,
        "statement": (
            f"{len(sessions)} SSH session(s) across {len(hosts)} host(s)"
            + (f"; {len(deprecated)} deprecated algorithm(s) in use: "
               + ", ".join(sorted(deprecated)) if deprecated else
               "; no deprecated algorithm in any session")
            + (f"; {len(asymmetric)} host(s) negotiate different ciphers per direction"
               if asymmetric else "")
            + (f"; {len(refused)} session(s) refused" if refused else "")),
        "not_proven": list(NOT_PROVEN),
    }


def to_algorithms(body: Mapping[str, Any]) -> dict[str, Any]:
    """SSH algorithms as CBOM facts, in the roles the rest of the platform uses."""
    if not isinstance(body, Mapping) or body.get("schema") != SCHEMA:
        raise ValueError(f"not a {SCHEMA} document")
    facts: list[dict[str, Any]] = []
    role_by_dimension = {"KEX": "KEY_EXCHANGE", "HOST_KEY": "SIGNATURE",
                         "CIPHER": "BULK", "MAC": "MAC"}
    for session_row in body.get("sessions") or []:
        collected = [session_row.get("kex"), session_row.get("host_key")]
        for direction in DIRECTIONS:
            collected.extend([session_row["directions"][direction]["cipher"],
                              session_row["directions"][direction]["mac"]])
        for row in collected:
            if not row:
                continue
            facts.append({
                "algorithm": row["algorithm"],
                "role": role_by_dimension[row["dimension"]],
                "dimension": row["dimension"],
                "parameters": ({"key_size": row["key_bits"]} if row["key_bits"] else {}),
                "aead": row["aead"],
                "quantum_vulnerable": bool(row["quantum_vulnerable"]),
                "host": session_row["host"],
                "evidence_ids": list(session_row["evidence_ids"]),
                "class": "NETWORK_OBSERVED",
                "protocol": "SSH",
            })
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for fact in facts:
        seen.setdefault((fact["host"], fact["role"], fact["algorithm"]), fact)
    return {
        "schema": SCHEMA,
        "facts": sorted(seen.values(), key=lambda fact: (fact["host"], fact["role"],
                                                         fact["algorithm"])),
        "endpoints": len({fact["host"] for fact in facts}),
        "quantum_vulnerable": sorted({fact["algorithm"] for fact in facts
                                      if fact["quantum_vulnerable"]}),
        "statement": (f"{len(seen)} distinct SSH algorithm fact(s) across "
                      f"{len({fact['host'] for fact in facts})} host(s)"),
    }


def summary(body: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: which hosts negotiate a deprecated algorithm, and in which direction."""
    sessions = body.get("sessions") or []
    deprecated = body.get("deprecated") or {}
    return {
        "schema": SCHEMA,
        "sessions": len(sessions),
        "hosts": len(body.get("hosts") or []),
        "asymmetric_directions": body.get("asymmetric_directions") or [],
        "deprecated": deprecated,
        "refused": len(body.get("refused") or []),
        "statement": body.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }

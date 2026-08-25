"""Lookup cryptographic libraries by package or binary name."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

ALIASES = {
    "bcpkix-jdk18on": "bouncycastle",
    "bcprov-jdk18on": "bouncycastle",
    "bcprov-jdk15on": "bouncycastle",
    "bcpkix-jdk15on": "bouncycastle",
    "bcprov": "bouncycastle",
    "bcpkix": "bouncycastle",
    "pyjwt": "pyjwt",
    "libssl3": "openssl",
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libcrypto3": "openssl",
    "libcrypto.so.3": "openssl",
    "libssl.so.3": "openssl",
    "openssl": "openssl",
    "libsodium": "libsodium",
    "libmbedcrypto": "mbedtls",
    "libmbedtls": "mbedtls",
    "mbedtls": "mbedtls",
}


class FingerprintRepository:
    def __init__(self, fingerprint_db: dict[str, Any] | None = None, path: Path | None = None):
        if fingerprint_db is not None:
            self.data = fingerprint_db
        else:
            db_path = path or (DATA_DIR / "fingerprint_db.json")
            self.data = json.loads(db_path.read_text(encoding="utf-8"))
        self._hashes = self._load_seed_hashes()

    def _load_seed_hashes(self) -> dict[str, dict[str, Any]]:
        hashes: dict[str, dict[str, Any]] = {}
        seed_dirs = (
            DATA_DIR / "seed",
            Path(__file__).resolve().parents[1] / "fingerprint_db" / "seed_data",
        )
        for seed_dir in seed_dirs:
            if not seed_dir.is_dir():
                continue
            for path in seed_dir.glob("*.json"):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                library = payload.get("library") or path.stem
                for entry in payload.get("entries") or []:
                    digest = str(entry.get("sha256") or "").lower()
                    if digest:
                        hashes[digest] = {
                            "library": library,
                            "version": entry.get("version"),
                            "file": entry.get("file"),
                        }
        return hashes

    def lookup_hash(self, digest: str | None) -> dict[str, Any] | None:
        info = self._hashes.get((digest or "").lower())
        if info is None:
            return None
        payload = dict(info)
        catalog = self.lookup(payload.get("library"))
        if catalog:
            payload.setdefault("algorithms", list(catalog.get("algorithms") or []))
            payload.setdefault("vendor", catalog.get("vendor"))
        return payload

    @property
    def libraries(self) -> dict[str, Any]:
        return self.data.get("libraries") or {}

    def canonical(self, name: str | None) -> str:
        raw = (name or "").lower()
        if raw in ALIASES:
            return ALIASES[raw]
        for alias, target in ALIASES.items():
            if raw.startswith(alias) or alias in raw:
                return target
        return raw

    def lookup(self, name: str | None) -> dict[str, Any] | None:
        info = self.libraries.get(self.canonical(name))
        return dict(info) if info else None

    def match_binary(self, filename: str | None) -> dict[str, Any] | None:
        lower = (filename or "").lower()
        if "libcrypto" in lower or "libssl" in lower:
            return self.lookup("openssl")
        if "libsodium" in lower:
            return self.lookup("libsodium")
        if "mbedtls" in lower or "mbedcrypto" in lower:
            return self.lookup("mbedtls")
        if "bcprov" in lower or "bcpkix" in lower or "bouncycastle" in lower:
            return self.lookup("bouncycastle")
        if "commons-codec" in lower:
            return self.lookup("commons-codec")
        stem = Path(lower).stem
        return self.lookup(stem)

    def algorithms_for(self, name: str | None) -> list[str]:
        info = self.lookup(name)
        if not info:
            return []
        return list(info.get("algorithms") or [])

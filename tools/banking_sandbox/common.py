"""Deterministic bounded file format; never fetch/resolve/connect to an estate address."""

import hashlib
import json
from pathlib import Path
import re

LABEL = "SYNTHETIC/LAB — NOT A REAL BANK OR PRODUCTION ASSET"
DIRECTORIES = [
    "load_balancers",
    "banks",
    "organizations",
    "assets",
    "systems",
    "applications",
    "source",
    "sbom",
    "cbom",
    "hbom",
    "vbom",
    "nbom",
    "techbom",
    "certificates",
    "pki",
    "hsm",
    "kms",
    "network",
    "containers",
    "kubernetes",
    "cloud",
    "vendors",
    "runtime",
    "fixtures",
    "scenarios",
    "drift",
    "pqc",
    "schemas",
    "docker",
    "compose",
    "docs",
]


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def number(seed, *parts):
    return int(hashlib.sha256(canonical([seed, *parts])).hexdigest()[:16], 16)


def identifier(*parts):
    return "lab-" + hashlib.sha256(canonical(parts)).hexdigest()[:24]


def dump(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(canonical(obj) + b"\n")


def stream(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        for row in rows:
            f.write(canonical(row) + b"\n")


def records(path):
    if path.is_symlink() or path.stat().st_size > 268435456:
        raise ValueError("record file type/budget")
    with path.open() as f:
        for line in f:
            if len(line) > 2097152:
                raise ValueError("record budget")

            def unique(pairs):
                d = {}
                for k, v in pairs:
                    if k in d:
                        raise ValueError("duplicate key")
                    d[k] = v
                return d

            yield json.loads(
                line, object_pairs_hook=unique, parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v))
            )


def inside(root, relative):
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts or str(p) != relative:
        raise ValueError("unsafe input reference")
    candidate = root / p
    if candidate.is_symlink() or not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("escaping reference")
    return candidate


def open_estate(root):
    root = Path(root).resolve(strict=True)
    meta = json.loads((root / "LAB.json").read_text())
    if meta.get("synthetic") is not True or meta.get("format") != "ZELNX_SYNTHETIC_ESTATE_V1":
        raise ValueError("not a lab estate")
    return root, meta


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest()


def safe_label(text):
    if not re.fullmatch("[a-zA-Z0-9_.-]{1,80}", text):
        raise ValueError("bounded synthetic label required")
    return text


def private_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError("output must be new")
    path.mkdir(mode=0o700, parents=True)
    return path

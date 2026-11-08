"""Deterministic public-only lab PKI. Signing seed is public fixture data, never production material."""

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from functools import lru_cache
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.x509.oid import NameOID


def lab_key(seed, label):
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"PUBLIC-SYNTHETIC-SEED:{seed}:{label}".encode()).digest()
    )


@lru_cache(maxsize=4)
def rsa_public(bits):
    return serialization.load_pem_public_key(
        (Path(__file__).with_name("fixtures") / f"SYNTHETIC-rsa-{bits}-public.pem").read_bytes()
    )


def certificate(seed, bank, index, timestamp):
    epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    level = {-1: "ROOT", -2: "INTERMEDIATE", -3: "ISSUING"}.get(index)
    parent = "ROOT" if index in (-1, -2) else "INTERMEDIATE" if index == -3 else "ISSUING"
    issuer_key = lab_key(seed, bank + "-" + parent)
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SYNTHETIC LAB ONLY"),
            x509.NameAttribute(NameOID.COMMON_NAME, bank + " SYNTHETIC " + parent),
        ]
    )
    if level:
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SYNTHETIC LAB ONLY"),
                x509.NameAttribute(NameOID.COMMON_NAME, bank + " SYNTHETIC " + level),
            ]
        )
        public = lab_key(seed, bank + "-" + level).public_key()
        kind = "Ed25519"
        ca = True
    else:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"endpoint-{index}.{bank}.lab.invalid")])
        variant = index % 7
        ca = False
        public = (
            rsa_public((1024, 2048, 3072, 4096)[variant])
            if variant < 4
            else ec.derive_private_key(
                1 + index % (2**128), ec.SECP256R1() if variant == 4 else ec.SECP384R1()
            ).public_key()
            if variant < 6
            else lab_key(seed, bank + str(index)).public_key()
        )
        kind = (
            "RSA-" + str((1024, 2048, 3072, 4096)[variant])
            if variant < 4
            else "ECDSA-P256"
            if variant == 4
            else "ECDSA-P384"
            if variant == 5
            else "Ed25519"
        )
    expired = index >= 0 and index % 17 == 0
    near = index >= 0 and index % 17 == 1
    before = epoch - timedelta(days=365)
    after = epoch + timedelta(days=-1 if expired else 2 if near else 3650 if ca else 180)
    serial = int.from_bytes(hashlib.sha256(f"{seed}:{bank}:{index}".encode()).digest()[:19], "big") or 1
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public)
        .serial_number(serial)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=2 if index == -1 else 1 if index == -2 else 0 if ca else None),
            critical=True,
        )
    )
    if not ca:
        cert = cert.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"endpoint-{index}.{bank}.lab.invalid")]), critical=False
        )
    signed = cert.sign(issuer_key, algorithm=None)
    return signed.public_bytes(serialization.Encoding.PEM), {
        "public_key_algorithm": kind,
        "signature_algorithm": "Ed25519",
        "serial": "SYNTHETIC-" + str(serial),
        "not_before": before.isoformat(),
        "not_after": after.isoformat(),
        "expiry_at_simulated_epoch": "EXPIRED" if expired else "NEAR_EXPIRY" if near else "VALID",
        "private_key_persisted": False,
        "synthetic_public_seed_ca": True,
        "clock_kind": "SIMULATED",
    }

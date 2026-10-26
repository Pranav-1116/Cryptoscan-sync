"""LOCAL LAB authority, not a production device identity or human-approval service.

Three distinct Ed25519 keys model issuer, reviewer and enrolled local adapter.
SQLite serializes one-time redemption/revocation. Never forward keys into the VM.
The store owner is trusted: this is not tamper-proof custody or multi-host PKI.
"""

from contextlib import contextmanager
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from tools.disposable_tbf.runner import canonical, strict_json

ROLES = ("issuer", "reviewer", "adapter")


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def public(key):
    return b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def sign(key, obj):
    return b64(key.sign(canonical(obj)))


def verify(pub, signature, obj):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub, validate=True)).verify(
            base64.b64decode(signature, validate=True), canonical(obj)
        )
    except Exception as exc:
        raise ValueError("invalid authenticated envelope") from exc


class Authority:
    def __init__(self, directory):
        self.directory = Path(directory)
        mode = self.directory.lstat()
        if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or mode.st_mode & 0o077:
            raise ValueError("private ordinary-user authority directory required")
        self.path = self.directory / "authority.sqlite"
        if self.path.is_symlink() or not self.path.is_file() or self.path.stat().st_mode & 0o077:
            raise ValueError("private authority database required")

    @classmethod
    def initialize(cls, directory, tenant="lab", device="diskless-routed-v1"):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        pubs = {}
        for role in ROLES:
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            fd = os.open(directory / (role + ".key"), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            pubs[role] = public(key)
        path = directory / "authority.sqlite"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with sqlite3.connect(path) as db:
            db.executescript("""
                CREATE TABLE enrollment (tenant TEXT, device TEXT, public_keys TEXT);
                CREATE TABLE leases (id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                    approval TEXT, state TEXT NOT NULL, redeemed_at REAL, revoked_at REAL);
                CREATE TABLE audit (sequence INTEGER PRIMARY KEY, at REAL, action TEXT, lease TEXT);
            """)
            db.execute("INSERT INTO enrollment VALUES (?,?,?)", (tenant, device, json.dumps(pubs)))
        return cls(directory)

    @contextmanager
    def transaction(self):
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def key(self, role):
        if role not in ROLES:
            raise ValueError("unknown key role")
        p = self.directory / (role + ".key")
        info = p.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError("private role key required")
        return Ed25519PrivateKey.from_private_bytes(p.read_bytes())

    def enrollment(self, db):
        tenant, device, pubs = db.execute("SELECT * FROM enrollment").fetchone()
        keys = strict_json(pubs)
        if len(set(keys.values())) != 3:
            raise ValueError("issuer/reviewer/adapter keys must be distinct")
        return tenant, device, keys

    def issue(self, tenant, device, bundle, acceptance, ttl=600, now=None):
        now = time.time() if now is None else now
        if not 330 <= ttl <= 600 or any(
            len(v) != 64 or any(c not in "0123456789abcdef" for c in v) for v in (bundle, acceptance)
        ):
            raise ValueError("bounded exact bundle/profile lease required")
        with self.transaction() as db:
            et, ed, _ = self.enrollment(db)
            if (tenant, device) != (et, ed):
                raise ValueError("wrong tenant or enrolled device")
            obj = {
                "version": "LAB_EXECUTION_LEASE_V1",
                "id": secrets.token_hex(32),
                "tenant": tenant,
                "device": device,
                "bundle_sha256": bundle,
                "acceptance_sha256": acceptance,
                "issued_at": now,
                "expires_at": now + ttl,
                "nonce": secrets.token_hex(32),
                "operation": "DISPOSABLE_ROUTED_VM_ONLY",
                "production_authorized": False,
            }
            envelope = {"payload": obj, "issuer_signature": sign(self.key("issuer"), obj)}
            db.execute(
                "INSERT INTO leases(id,payload,state) VALUES (?,?,?)",
                (obj["id"], canonical(envelope).decode(), "ISSUED"),
            )
            db.execute("INSERT INTO audit(at,action,lease) VALUES (?,?,?)", (now, "ISSUED", obj["id"]))
        return envelope

    def approve(self, envelope, acknowledge_simulated_reviewer=False):
        if not acknowledge_simulated_reviewer:
            raise ValueError("explicit separate simulated-reviewer acknowledgement required")
        p = envelope["payload"]
        approval = {
            "lease_sha256": hashlib.sha256(canonical(envelope)).hexdigest(),
            "reviewer_role": "SEPARATE_LAB_REVIEWER_KEY",
            "independent_human_approval": False,
        }
        approval["signature"] = sign(self.key("reviewer"), approval)
        with self.transaction() as db:
            _, _, keys = self.enrollment(db)
            verify(keys["issuer"], envelope["issuer_signature"], p)
            row = db.execute("SELECT payload,state FROM leases WHERE id=?", (p["id"],)).fetchone()
            if (
                not row
                or row != (canonical(envelope).decode(), "ISSUED")
                or not p["issued_at"] <= time.time() < p["expires_at"]
            ):
                raise ValueError("approval requires current unmodified issued lease")
            db.execute(
                "UPDATE leases SET approval=?,state=? WHERE id=?", (canonical(approval).decode(), "APPROVED", p["id"])
            )
            db.execute(
                "INSERT INTO audit(at,action,lease) VALUES (?,?,?)", (time.time(), "APPROVED_LAB_KEY_ONLY", p["id"])
            )
        return {"lease": envelope, "approval": approval}

    def redeem(self, grant, tenant, device, bundle, acceptance, now=None):
        now = time.time() if now is None else now
        envelope, approval = grant["lease"], dict(grant["approval"])
        p = envelope["payload"]
        with self.transaction() as db:
            et, ed, keys = self.enrollment(db)
            if (tenant, device) != (et, ed) or (p["tenant"], p["device"]) != (tenant, device):
                raise ValueError("wrong tenant or device")
            verify(keys["issuer"], envelope["issuer_signature"], p)
            sig = approval.pop("signature")
            verify(keys["reviewer"], sig, approval)
            if (
                approval
                != {
                    "lease_sha256": hashlib.sha256(canonical(envelope)).hexdigest(),
                    "reviewer_role": "SEPARATE_LAB_REVIEWER_KEY",
                    "independent_human_approval": False,
                }
                or p["bundle_sha256"] != bundle
                or p["acceptance_sha256"] != acceptance
                or p["operation"] != "DISPOSABLE_ROUTED_VM_ONLY"
                or p["production_authorized"] is not False
                or p["version"] != "LAB_EXECUTION_LEASE_V1"
                or not 330 <= p["expires_at"] - p["issued_at"] <= 600
                or not p["issued_at"] <= now <= p["expires_at"] - 305
            ):
                raise ValueError("lease context, operation or full execution window invalid")
            row = db.execute("SELECT payload,approval,state FROM leases WHERE id=?", (p["id"],)).fetchone()
            if not row or row != (canonical(envelope).decode(), canonical(grant["approval"]).decode(), "APPROVED"):
                raise ValueError("lease revoked, replayed or approval mismatched")
            # Adapter proves possession over this exact issuer/reviewer grant before one-time redemption.
            proof = {"grant_sha256": hashlib.sha256(canonical(grant)).hexdigest(), "challenge": p["nonce"]}
            proof["signature"] = sign(self.key("adapter"), proof)
            verify(keys["adapter"], proof["signature"], {k: v for k, v in proof.items() if k != "signature"})
            db.execute("UPDATE leases SET state=?,redeemed_at=? WHERE id=?", ("REDEEMED", now, p["id"]))
            db.execute("INSERT INTO audit(at,action,lease) VALUES (?,?,?)", (now, "REDEEMED_ONCE", p["id"]))
        return proof

    def active(self, lease_id):
        with sqlite3.connect(self.path, timeout=1) as db:
            row = db.execute("SELECT state,payload FROM leases WHERE id=?", (lease_id,)).fetchone()
        if not row or row[0] != "REDEEMED":
            return False
        p = strict_json(row[1])["payload"]
        return p["issued_at"] <= time.time() < p["expires_at"]

    def revoke(self, lease_id):
        with self.transaction() as db:
            row = db.execute("SELECT state FROM leases WHERE id=?", (lease_id,)).fetchone()
            if not row:
                raise ValueError("unknown lease")
            db.execute("UPDATE leases SET state=?,revoked_at=? WHERE id=?", ("REVOKED", time.time(), lease_id))
            db.execute("INSERT INTO audit(at,action,lease) VALUES (?,?,?)", (time.time(), "REVOKED", lease_id))

    def sign_receipt(self, value):
        return {
            "payload": value,
            "adapter_signature": sign(self.key("adapter"), value),
            "adapter_public_key": public(self.key("adapter")),
            "trust": "LOCAL_LAB_ENROLLED_ADAPTER_NOT_PHYSICAL_DEVICE_ATTESTATION",
        }

"""Repository for users, sessions, and the audit trail."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.user import AuditLog, User, UserSession, VALID_ROLES

GENESIS_HASH = "0" * 64


def _aware_iso(value) -> str:
    """Naive datetimes (sqlite) must hash identically to aware ones."""
    from shared_models.chrono import aware

    return aware(value).isoformat() if value is not None else ""


def audit_entry_hash(row: AuditLog, *, previous_hash: str | None) -> str:
    """SHA-256 over the canonical entry — any later edit breaks the chain."""
    import hashlib

    canonical = "|".join(
        [
            str(previous_hash or GENESIS_HASH),
            str(row.actor or ""),
            str(row.action or ""),
            str(row.target_type or ""),
            str(row.target_id or ""),
            str(row.detail or ""),
            str(row.ip_address or ""),
            str(row.outcome or ""),
            _aware_iso(row.created_at),
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit_chain(session: Session) -> dict:
    """Walk the chain in sequence order; report the first break honestly."""
    rows = list(
        session.execute(
            select(AuditLog).where(AuditLog.chain_sequence.is_not(None)).order_by(AuditLog.chain_sequence)
        ).scalars()
    )
    expected_prev = GENESIS_HASH
    checked = 0
    for row in rows:
        if row.previous_hash != expected_prev:
            return {
                "status": "TAMPERED",
                "checked": checked,
                "entry_count": len(rows),
                "break_at_sequence": row.chain_sequence,
                "reason": "previous_hash mismatch (entry removed, reordered, or forged)",
            }
        if audit_entry_hash(row, previous_hash=row.previous_hash) != row.entry_hash:
            return {
                "status": "TAMPERED",
                "checked": checked,
                "entry_count": len(rows),
                "break_at_sequence": row.chain_sequence,
                "reason": "entry_hash mismatch (entry content modified after write)",
            }
        expected_prev = row.entry_hash
        checked += 1
    return {
        "status": "OK",
        "checked": checked,
        "entry_count": len(rows),
        "chain_head": expected_prev if rows else None,
    }


# --------------------------------------------------------------------------- #
# Incremental anchor verification
#
# The audit chain grows forever (regulatory retention is 5+ years), but the
# chain's structure means an honest verifier does not need to re-walk every
# row on every check: re-anchor at the last verified head and verify only the
# appended suffix. A full walk still runs on cold start, when the anchor is
# invalidated (truncation / tamper at or before the anchor), when forced, or
# when the last full walk is older than `full_max_age_days` — bounding how far
# back an undetected pre-anchor edit can be.
# --------------------------------------------------------------------------- #
_ANCHOR_KEY = "audit_chain_anchor"


def _load_chain_anchor(session: Session) -> dict | None:
    from db.repositories.settings_repository import SettingsRepository

    anchor = SettingsRepository(session).get(_ANCHOR_KEY)
    return anchor if isinstance(anchor, dict) else None


def _save_chain_anchor(session: Session, *, sequence: int, head: str,
                       full_verified_at: str) -> None:
    from db.repositories.settings_repository import SettingsRepository

    SettingsRepository(session).set(_ANCHOR_KEY, {
        "sequence": int(sequence),
        "head": str(head),
        "full_verified_at": full_verified_at,
    })


def _anchor_is_fresh(anchor: dict, full_max_age_days: int) -> bool:
    raw = anchor.get("full_verified_at")
    if not raw:
        return False
    try:
        ts = datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - ts
    return age <= timedelta(days=int(full_max_age_days))


def verify_audit_chain_incremental(session: Session, *, force_full: bool = False,
                                   full_max_age_days: int = 7) -> dict:
    """Verify the audit chain with O(new rows) cost per call.

    Returns the same shape as :func:`verify_audit_chain` plus:
      mode              "full" | "incremental"
      full_verified_at  ISO time of the most recent full walk
      entry_count       total chained entries (chain size)

    Tamper classes caught (a superset of the full walk):
      * content edit anywhere after the anchor head      (suffix hash re-check)
      * deletion / reordering after the anchor head      (link + gap re-check)
      * tail truncation below the anchored head          (NEW — undetectable
        by a plain walk of the remaining chain)
      * content edit at or before the anchor head        (full-walk fallback,
        at most once per `full_max_age_days` window)
    """
    anchor = None if force_full else _load_chain_anchor(session)
    if (anchor is None
            or not anchor.get("sequence")
            or not anchor.get("head")
            or not _anchor_is_fresh(anchor, full_max_age_days)):
        result = verify_audit_chain(session)
        result["mode"] = "full"
        if result["status"] == "OK":
            now_iso = datetime.now(timezone.utc).isoformat()
            # Anchor at the TOP SEQUENCE VALUE (not the row count): the chain
            # is normally dense, but the anchor must survive any gap.
            top = session.execute(
                select(func.max(AuditLog.chain_sequence))
                .where(AuditLog.chain_sequence.is_not(None))
            ).scalar_one()
            _save_chain_anchor(session, sequence=int(top or 0),
                               head=result["chain_head"] or "",
                               full_verified_at=now_iso)
            result["full_verified_at"] = now_iso
        return result

    anchor_seq = int(anchor["sequence"])
    anchor_head = str(anchor["head"])

    top = session.execute(
        select(func.max(AuditLog.chain_sequence))
        .where(AuditLog.chain_sequence.is_not(None))
    ).scalar_one()
    if top is None or int(top) < anchor_seq:
        # Entries vanished below the last verified head: the anchored entry is
        # gone, which a plain walk of the surviving prefix would report OK.
        return {
            "status": "TAMPERED",
            "checked": 0,
            "entry_count": int(top or 0),
            "break_at_sequence": anchor_seq,
            "reason": "chain truncated below last verified head (entries deleted)",
            "chain_head": None,
            "mode": "incremental",
            "full_verified_at": anchor.get("full_verified_at"),
        }

    row = session.execute(
        select(AuditLog).where(AuditLog.chain_sequence == anchor_seq)
    ).scalar_one_or_none()
    if (row is None
            or row.entry_hash != anchor_head
            or audit_entry_hash(row, previous_hash=row.previous_hash) != row.entry_hash):
        # The anchor itself no longer verifies — including the lazy-attacker
        # case where the anchor row's CONTENT is edited while its stored hash
        # column (and every later row's link) is left intact: the stored-hash
        # comparison alone would trust a row whose bytes no longer hash to it,
        # and the incremental pass never re-hashes the anchor row itself. One
        # SHA-256 closes that. Fall back to a full walk to locate the break
        # honestly (and refresh the anchor if it comes back OK).
        result = verify_audit_chain(session)
        result["mode"] = "full"
        if result["status"] == "OK":
            now_iso = datetime.now(timezone.utc).isoformat()
            top = session.execute(
                select(func.max(AuditLog.chain_sequence))
                .where(AuditLog.chain_sequence.is_not(None))
            ).scalar_one()
            _save_chain_anchor(session, sequence=int(top or 0),
                               head=result["chain_head"] or "",
                               full_verified_at=now_iso)
            result["full_verified_at"] = now_iso
        return result

    suffix = list(session.execute(
        select(AuditLog).where(AuditLog.chain_sequence > anchor_seq)
        .order_by(AuditLog.chain_sequence)
    ).scalars())
    entry_count = anchor_seq + len(suffix)

    expected_prev = anchor_head
    prev_seq = anchor_seq
    checked = 0
    for r in suffix:
        if r.chain_sequence <= prev_seq:
            reason = ("sequence not increasing after anchored head "
                      "(entry removed, reordered, or forged)")
        elif r.previous_hash != expected_prev:
            reason = ("previous_hash mismatch after anchored head "
                      "(entry removed, reordered, or forged)")
        else:
            reason = None
        if reason:
            return {
                "status": "TAMPERED",
                "checked": checked,
                "entry_count": entry_count,
                "break_at_sequence": r.chain_sequence,
                "reason": reason,
                "chain_head": None,
                "mode": "incremental",
                "full_verified_at": anchor.get("full_verified_at"),
            }
        if audit_entry_hash(r, previous_hash=r.previous_hash) != r.entry_hash:
            return {
                "status": "TAMPERED",
                "checked": checked,
                "entry_count": entry_count,
                "break_at_sequence": r.chain_sequence,
                "reason": "entry_hash mismatch (entry content modified after write)",
                "chain_head": None,
                "mode": "incremental",
                "full_verified_at": anchor.get("full_verified_at"),
            }
        expected_prev = r.entry_hash
        prev_seq = int(r.chain_sequence)
        checked += 1

    _save_chain_anchor(session, sequence=prev_seq, head=expected_prev,
                       full_verified_at=str(anchor.get("full_verified_at")))
    return {
        "status": "OK",
        "checked": checked,
        "entry_count": prev_seq,
        "chain_head": expected_prev,
        "mode": "incremental",
        "full_verified_at": anchor.get("full_verified_at"),
    }


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserRepository:
    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------ users

    def count_users(self) -> int:
        from sqlalchemy import func

        return int(self.session.execute(select(func.count()).select_from(User)).scalar_one())

    def get_by_username(self, username: str) -> User | None:
        return self.session.execute(
            select(User).where(User.username == (username or "").strip().lower())
        ).scalar_one_or_none()

    def _known_role_names(self) -> set[str]:
        """Built-in role names plus the custom roles defined in this
        deployment (round 30): a custom role survives assignment instead
        of silently degrading to the viewer default."""
        names = set(VALID_ROLES)
        try:
            from db.models.custom_role import CustomRole

            rows = self.session.query(CustomRole.name).all()
            names.update(str(r[0]).strip().lower() for r in rows if r[0])
        except Exception:  # noqa: BLE001 — no table / read error: built-ins
            pass
        return names

    def create_user(
        self,
        username: str,
        password_hash: str,
        roles: list[str] | None = None,
        *,
        display_name: str | None = None,
        email: str | None = None,
        is_active: bool = True,
    ) -> User:
        known = self._known_role_names()
        clean_roles = sorted({r for r in (roles or ["viewer"]) if r in known}) or ["viewer"]
        user = User(
            username=(username or "").strip().lower(),
            password_hash=password_hash,
            roles=",".join(clean_roles),
            display_name=display_name,
            email=email,
            is_active=is_active,
        )
        self.session.add(user)
        self.session.flush()
        return user

    def set_roles(self, username: str, roles: list[str]) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        known = self._known_role_names()
        clean = sorted({r for r in roles if r in known})
        user.roles = ",".join(clean) if clean else user.roles
        self.session.flush()
        return user

    def set_active(self, username: str, is_active: bool) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.is_active = is_active
        if is_active:
            user.failed_attempts = 0
            user.locked_until = None
        self.session.flush()
        return user

    def soft_delete_user(self, username: str) -> User | None:
        """Soft-delete a user (compliance-safe): mark deleted_at, disable the
        account. The row is retained so the audit hash chain and historical
        actor references remain verifiable. Idempotent — re-deleting an
        already-removed account returns the row without changing the
        original deletion timestamp. Returns None if no such user."""
        user = self.get_by_username(username)
        if user is None:
            return None
        if user.deleted_at is None:
            user.deleted_at = datetime.now(timezone.utc)
        user.is_active = False
        self.session.flush()
        return user

    def restore_user(self, username: str) -> User | None:
        """Undo a soft delete: clear deleted_at and re-enable the account."""
        user = self.get_by_username(username)
        if user is None or user.deleted_at is None:
            return None
        user.deleted_at = None
        user.is_active = True
        user.failed_attempts = 0
        user.locked_until = None
        self.session.flush()
        return user

    def list_active_users(self) -> list[User]:
        """Users that are neither soft-deleted nor disabled (login candidates)."""
        return list(
            self.session.execute(
                select(User).where(User.deleted_at.is_(None), User.is_active.is_(True))
            ).scalars().all()
        )

    def set_password(self, username: str, password_hash: str) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.password_hash = password_hash
        user.failed_attempts = 0
        user.locked_until = None
        self.session.flush()
        return user

    def list_users(self) -> list[User]:
        return list(self.session.execute(select(User).order_by(User.username)).scalars().all())

    # ---------------------------------------------------------------- lockout

    def record_failure(self, username: str, *, max_failures: int, lockout_seconds: int) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= max_failures:
            user.locked_until = datetime.now(timezone.utc) + timedelta(seconds=lockout_seconds)
            user.failed_attempts = 0
        self.session.flush()
        return user

    def reset_failures(self, username: str) -> None:
        user = self.get_by_username(username)
        if user is not None:
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login_at = datetime.now(timezone.utc)
            self.session.flush()

    # --------------------------------------------------------------- sessions

    def create_session(self, token: str, username: str, expires_at: datetime, ip: str | None = None) -> UserSession:
        row = UserSession(
            token_hash=token_hash(token),
            username=username,
            created_at_ts=datetime.now(timezone.utc),
            expires_at=expires_at,
            ip_address=ip,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def get_session(self, token: str) -> UserSession | None:
        return self.session.execute(
            select(UserSession).where(UserSession.token_hash == token_hash(token))
        ).scalar_one_or_none()

    def revoke_session(self, token: str) -> bool:
        row = self.get_session(token)
        if row is None:
            return False
        row.revoked_at = datetime.now(timezone.utc)
        self.session.flush()
        return True

    def revoke_all_sessions(self, username: str) -> int:
        rows = list(
            self.session.execute(
                select(UserSession).where(
                    UserSession.username == username,
                    UserSession.revoked_at.is_(None),
                )
            ).scalars().all()
        )
        now = datetime.now(timezone.utc)
        for row in rows:
            row.revoked_at = now
        self.session.flush()
        return len(rows)

    def revoke_other_sessions(self, username: str, keep_token: str) -> int:
        """Revoke every active session for ``username`` except ``keep_token``.

        Used by self-service credential rotation: the caller's current
        session stays valid so they are not logged out mid-request, while any
        token on another device/browser is invalidated. Returns the count of
        sessions revoked.
        """
        keep_hash = token_hash(keep_token) if keep_token else ""
        rows = list(
            self.session.execute(
                select(UserSession).where(
                    UserSession.username == username,
                    UserSession.revoked_at.is_(None),
                    UserSession.token_hash != keep_hash,
                )
            ).scalars().all()
        )
        now = datetime.now(timezone.utc)
        for row in rows:
            row.revoked_at = now
        self.session.flush()
        return len(rows)

    def count_active_sessions(self, username: str) -> int:
        """Number of sessions for a user that have not been revoked and have
        not expired (expiry is best-effort here; expired rows are harmless)."""
        from sqlalchemy import func

        return int(
            self.session.execute(
                select(func.count())
                .select_from(UserSession)
                .where(
                    UserSession.username == username,
                    UserSession.revoked_at.is_(None),
                )
            ).scalar_one()
        )

    # ------------------------------------------------------------------ audit



    # ---------------------------------------------------------------- mfa

    def set_mfa_secret(self, username: str, secret_b32: str | None, *, enabled: bool) -> User | None:
        user = self.get_by_username(username)
        if user is None:
            return None
        user.mfa_secret = secret_b32
        user.mfa_enabled = bool(enabled and secret_b32)
        self.session.flush()
        return user

    def set_recovery_codes(self, user_id: str, code_hashes: list[str]) -> None:
        from datetime import datetime, timezone

        from db.models.user import MfaRecoveryCode

        self.session.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user_id).delete()
        now = datetime.now(timezone.utc)
        from uuid import uuid4

        for code_hash in code_hashes:
            self.session.add(
                MfaRecoveryCode(id=str(uuid4()), user_id=user_id, code_hash=code_hash, created_at=now)
            )
        self.session.flush()

    def consume_recovery_code(self, user_id: str, code_hash: str) -> bool:
        """Mark a code used exactly once; False if unknown or already spent."""
        from datetime import datetime, timezone

        from db.models.user import MfaRecoveryCode

        row = (
            self.session.query(MfaRecoveryCode)
            .filter(
                MfaRecoveryCode.user_id == user_id,
                MfaRecoveryCode.code_hash == code_hash,
                MfaRecoveryCode.used_at.is_(None),
            )
            .one_or_none()
        )
        if row is None:
            return False
        row.used_at = datetime.now(timezone.utc)
        self.session.flush()
        return True

    def audit(
        self,
        actor: str,
        action: str,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        detail: dict | str | None = None,
        ip: str | None = None,
        outcome: str = "SUCCESS",
    ) -> AuditLog:
        if isinstance(detail, (dict, list)):
            detail = json.dumps(detail, default=str)
        from db.models.base import utcnow as _utcnow

        head = self._audit_chain_head()
        row = AuditLog(
            created_at=_utcnow(),  # hash covers a real timestamp, never the pre-flush None
            actor=actor or "unknown",
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
            ip_address=ip,
            outcome=outcome,
            chain_sequence=head["sequence"] + 1,
            previous_hash=head["entry_hash"],
        )
        row.entry_hash = audit_entry_hash(row, previous_hash=head["entry_hash"])
        self.session.add(row)
        self.session.flush()
        return row

    def _audit_chain_head(self) -> dict:
        """Latest chained entry (sequence, entry_hash); GENESIS when empty/un-chained."""
        row = (
            self.session.execute(
                select(AuditLog)
                .where(AuditLog.chain_sequence.is_not(None))
                .order_by(AuditLog.chain_sequence.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if row is None:
            return {"sequence": 0, "entry_hash": GENESIS_HASH}
        return {"sequence": row.chain_sequence, "entry_hash": row.entry_hash}

    def list_audit(self, *, page: int = 1, page_size: int = 50, actor: str | None = None, action: str | None = None):
        stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
        if actor:
            stmt = stmt.where(AuditLog.actor == actor)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        rows = list(
            self.session.execute(
                stmt.offset((page - 1) * page_size).limit(page_size)
            ).scalars().all()
        )
        return rows

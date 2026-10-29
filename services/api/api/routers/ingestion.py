"""The bundle ingestion gate — what a bank-side collector's transfer must prove (spec 100).

The estate engine (spec 93) projects six BOMs from one evidence graph. This router is
how that evidence arrives from the bank's side: the collector packages evidence, signs
the manifest, and the platform verifies before anything is normalised.

Two routes, and they are deliberately small:

* ``GET /ingestion/bundles/schema`` — the format, its member layout, its reason codes and
  its limits, so a collector does not have to guess what the receiver accepts;
* ``POST /ingestion/bundles/verify`` — verify one bundle and report exactly what it proved.

Three things this router refuses to do:

* **it does not accept a bundle nobody can vouch for.** ``accepted`` is true only when the
  manifest signature verifies against a key this deployment was configured to trust.
  Without such a key the answer is ``SIGNATURE_UNCHECKED`` with the deployment fact stated,
  not a shrug and an ingest;
* **it does not report a transport success as an ingestion.** The verdict is the module's
  verdict; the route adds no optimism, and ``projection`` says ``NOT_ATTEMPTED`` because
  normalisation, identity resolution and the six projections are a later stage that this
  build does not yet run from a bundle;
* **it does not let a large body through quietly.** A transfer above the configured ceiling
  is refused with ``BUNDLE_TOO_LARGE``; chunked upload is not implemented and saying so is
  better than a truncated ingest.

The trusted collector key is deployment configuration, not a request field: a caller who
could nominate the key to trust could authorise their own bundle.
"""

from __future__ import annotations

import base64
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import get_current_user
from shared_models import evidence_bundle, release_signature

router = APIRouter(prefix="/ingestion", tags=["ingestion"])

#: bytes a single verification request may carry. Chunked transfer is not built.
MAX_BUNDLE_BYTES = int(os.getenv("CRYPTOSCAN_BUNDLE_MAX_BYTES", str(64 * 1024 * 1024)))

#: where this deployment's trusted collector keys live: base64 Ed25519 public keys or
#: paths to PEM files, separated by the platform path separator or a comma.
TRUST_KEY_ENV = "CRYPTOSCAN_BUNDLE_TRUST_KEYS"

NO_TRUSTED_KEY = "NO_TRUSTED_COLLECTOR_KEY"
BAD_MEMBER_ENCODING = "MEMBER_NOT_BASE64"
BUNDLE_TOO_LARGE = "BUNDLE_TOO_LARGE"


class BundleVerifyRequest(BaseModel):
    """A bundle in one piece: the signed manifest and its members, base64 per member."""

    manifest: dict = Field(description="the manifest exactly as the collector signed it")
    members: dict[str, str] = Field(
        default_factory=dict,
        description="member path -> base64 bytes; every member the manifest lists must be here",
    )


def trusted_keys() -> list:
    """Load the keys this deployment trusts for collector bundles.

    An unreadable entry is skipped rather than silently trusted: a typo in the key path
    must degrade to "no key configured", which refuses bundles, not to "any key will do".
    """
    raw = os.getenv(TRUST_KEY_ENV, "").strip()
    if not raw:
        return []
    keys = []
    for candidate in raw.replace(",", os.pathsep).split(os.pathsep):
        entry = candidate.strip()
        if not entry:
            continue
        try:
            keys.append(release_signature.load_public_key(entry))
        except Exception:  # noqa: BLE001 — a broken trust entry is skipped, not trusted
            continue
    return keys


@router.get("/bundles/schema")
def bundle_schema(_user: str = Depends(get_current_user)) -> dict:
    """The bundle format as this build accepts it, with its limits stated."""
    return {
        "schema": evidence_bundle.BUNDLE_SCHEMA,
        "signature_schema": release_signature.SCHEMA,
        "member_kinds": list(evidence_bundle.MEMBER_KINDS),
        "bundle_files": list(evidence_bundle.BUNDLE_FILES),
        "coverage_keys": list(evidence_bundle.COVERAGE_KEYS),
        "states": [
            evidence_bundle.VERIFIED,
            evidence_bundle.UNSIGNED,
            evidence_bundle.SIGNATURE_UNCHECKED,
            evidence_bundle.REJECTED,
        ],
        "reason_codes": sorted(
            code
            for name, code in vars(evidence_bundle).items()
            if name.isupper() and isinstance(code, str) and name not in {"BUNDLE_SCHEMA", "TRUST_KEY_ENV"}
        ),
        "trust": {
            "configured": bool(trusted_keys()),
            "source": f"deployment configuration ({TRUST_KEY_ENV}); a request cannot nominate its own key",
        },
        "max_request_bytes": MAX_BUNDLE_BYTES,
        "projection": "NOT_ATTEMPTED",
        "limits": evidence_bundle.LIMITS,
    }


@router.post("/bundles/verify")
def verify_bundle(body: BundleVerifyRequest, _user: str = Depends(get_current_user)) -> dict:
    """Verify one bundle. ``accepted`` is true only for a key-verified, intact bundle."""
    total = 0
    members: dict[str, bytes] = {}
    for path, encoded in (body.members or {}).items():
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception:  # noqa: BLE001 — a bad encoding is a verdict, not a 500
            raise HTTPException(422, f"{BAD_MEMBER_ENCODING}: {path} is not base64")
        total += len(data)
        if total > MAX_BUNDLE_BYTES:
            raise HTTPException(413, f"{BUNDLE_TOO_LARGE}: this transfer exceeds {MAX_BUNDLE_BYTES} bytes")
        members[str(path)] = data

    keys = trusted_keys()
    result = evidence_bundle.verify_bundle(body.manifest, members, trusted_key=keys[0] if keys else None)

    deployment: list[str] = []
    if not keys:
        deployment.append(
            f"{NO_TRUSTED_KEY}: no collector key is configured on this deployment "
            f"({TRUST_KEY_ENV}), so no bundle can reach {evidence_bundle.VERIFIED} here"
        )
    if len(keys) > 1:
        deployment.append(
            f"{len(keys)} collector keys are configured; only the first was used for this "
            "verdict, so a bundle signed by another trusted key reports a key mismatch"
        )

    return {
        **result,
        "received": {
            "members": len(members),
            "bytes": total,
            "manifest_member_count": result.get("member_count"),
        },
        "trusted_keys_configured": len(keys),
        "deployment_findings": deployment,
        "projection": {
            "state": "NOT_ATTEMPTED",
            "reason": (
                "verification is a gate, not an ingest: this build does not yet normalise a "
                "bundle, resolve identities or project the six BOMs from it"
            ),
        },
    }

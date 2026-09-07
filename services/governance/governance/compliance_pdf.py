"""Scheduled, signed compliance reports with per-framework templates.

Deterministic (no AI): maps platform evidence (findings, controls, assets) to
fixed framework controls for NIST SP 800-53, PCI-DSS 4.0, DORA, and UAE PDPL,
and renders a real PDF 1.4 document with a hand-written minimal writer (no
third-party dependency). Each report is signed (HMAC-SHA256 over a canonical
summary) so a scheduled PDF can be verified later.

Evidence is grouped into a normalized "evidence rows" model:
  {"control":"...","status":"PASS|FAIL|PARTIAL|NO_EVIDENCE","evidence":[{"id",
    "title","source","ref","detail"}]}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import zlib
from dataclasses import dataclass, field
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Framework control catalogues (deterministic mapping keyed to platform
# evidence categories). Each control maps the platform's own evidence tags.
# ---------------------------------------------------------------------------
FRAMEWORKS: dict[str, dict[str, Any]] = {
    "NIST_SP_800_53": {
        "title": "NIST SP 800-53 Security Controls",
        "controls": {
            "AC-2":  ("Account Management", "iam", "Account provisioning/deprovisioning (SCIM)"),
            "AC-3":  ("Access Enforcement", "rbac", "8-role RBAC enforcement"),
            "AC-17": ("Remote Access", "sso", "SAML/LDAP SSO + MFA"),
            "AU-2":  ("Event Logging", "audit", "Hash-chained audit events"),
            "AU-9":  ("Protection of Audit Information", "audit-chain", "Tamper-evident audit chain"),
            "IA-2":  ("Identification and Authentication", "sso", "Federated identity"),
            "IA-5":  ("Authenticator Management", "apikey", "API-key IP allowlist + rotation"),
            "SC-8":  ("Transmission Confidentiality", "tls", "TLS 1.2/1.3 + cipher posture"),
            "SC-12": ("Cryptographic Key Establishment", "hsm", "HSM/KMS key residence"),
            "SC-28": ("Protection of Information at Rest", "encryption", "Encryption at rest (S3/KMS)"),
            "SA-15": ("Development Process / Supply Chain", "sbom", "SBOM + container CVE scanning"),
            "SI-2":  ("Flaw Remediation", "cve", "Vulnerability detection and remediation SLAs"),
            "SI-4":  ("System Monitoring", "monitor", "Continuous monitoring/alerts"),
        },
    },
    "PCI_DSS_4": {
        "title": "PCI-DSS 4.0 Requirements",
        "controls": {
            "1.2":   ("Network security controls / NSC config", "firewall", "Security-group posture"),
            "2.2":   ("Secure configurations", "misconfig", "K8s/IaC misconfiguration rules"),
            "4.2":   ("Strong cryptography for PAN over networks", "tls", "TLS protocol/cipher audit"),
            "6.3":   ("Secure software development", "sast", "Weak-primitive code rules"),
            "7.2":   ("Least privilege", "rbac", "RBAC role enforcement"),
            "8.3":   ("Strong authentication / MFA", "sso", "SSO + MFA"),
            "10.2":  ("Audit logs", "audit", "Chained audit logging"),
            "11.3":  ("Vulnerability scanning", "cve", "Container + host CVE matching"),
            "11.6":   ("Bespoke/rogue certificates", "ct", "Certificate-transparency monitoring"),
            "12.10": ("Incident response", "alerts", "Alert routing/escalation"),
        },
    },
    "DORA": {
        "title": "DORA — ICT Risk Management & Incident Reporting",
        "controls": {
            "Art.9":  ("ICT risk-management framework", "posture", "Cloud/security posture"),
            "Art.11": ("Business continuity & DR", "backup", "Encrypted backup + restore"),
            "Art.13": ("Digital operational resilience testing", "cve", "Continuous vulnerability testing"),
            "Art.15": ("IC3 major incident detection", "monitor", "Monitoring and incident detection"),
            "Art.16": ("Incident response readiness", "alerts", "Alerting + ticketing integration"),
            "Art.26": ("Patch / vulnerability management", "cve", "Patch SLAs / expiry calendars"),
        },
    },
    "UAE_PDPL": {
        "title": "UAE Personal Data Protection Law (PDPL)",
        "controls": {
            "Art.9":  ("Security of personal data", "encryption", "Encryption in transit/at rest"),
            "Art.10": ("Access control to personal data", "rbac", "ABAC/RBAC data access"),
            "Art.13": ("Data breach notification readiness", "alerts", "Breach detection + alerting"),
            "Art.17": ("Records / accountability", "audit", "Tamper-evident audit records"),
            "Art.20": ("Transfer security (cryptography)", "tls", "TLS for data in transit"),
        },
    },
}


@dataclass
class EvidenceItem:
    id: str
    title: str
    source: str
    status: str = "PASS"          # PASS / FAIL / PARTIAL
    ref: str = ""
    detail: str = ""


def map_evidence(framework: str, evidence_tags: dict[str, list[dict]]) -> dict[str, Any]:
    """Map collected evidence-by-tag to framework controls deterministically.

    ``evidence_tags`` maps a tag (e.g. "tls", "audit", "cve") to evidence items
    each with a ``status``. Control status = worst status across mapped evidence
    (FAIL > PARTIAL > NO_EVIDENCE > PASS).
    """
    fw = FRAMEWORKS[framework]
    order = {"FAIL": 3, "PARTIAL": 2, "PASS": 0, "NO_EVIDENCE": 1}
    rows = []
    counts = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "NO_EVIDENCE": 0}
    for cid, (title, tag, _mapping) in fw["controls"].items():
        items = evidence_tags.get(tag, [])
        if not items:
            status = "NO_EVIDENCE"
        else:
            status = max((i.get("status", "PASS") for i in items), key=lambda s: order.get(s, 1))
        counts[status] += 1
        rows.append({"control": cid, "title": title, "status": status,
                     "evidence": items})
    return {"framework": framework, "framework_title": fw["title"],
            "control_rows": rows, "counts": counts,
            "compliance_pct": round(100 * counts["PASS"] / max(1, len(rows)))}


def canonical_summary(framework: str, mapping: dict[str, Any], *,
                      org: str, generated_at: str) -> bytes:
    """Deterministic canonical bytes that the signature covers."""
    payload = {
        "framework": framework, "org": org, "generated_at": generated_at,
        "counts": mapping["counts"], "compliance_pct": mapping["compliance_pct"],
        "controls": [(r["control"], r["status"]) for r in mapping["control_rows"]],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_summary(canonical: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()


def verify_summary(canonical: bytes, secret: str, signature: str) -> bool:
    return hmac.compare_digest(sign_summary(canonical, secret), signature)


# ---------------------------------------------------------------------------
# Minimal deterministic PDF 1.4 writer (Helvetica core font, pages of lines).
# ---------------------------------------------------------------------------
def _esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf(*, framework: str, org: str, generated_at: str,
               mapping: dict[str, Any], signature: str, author: str = "CryptoScan") -> bytes:
    """Render a multi-page compliance PDF. Deterministic given inputs."""
    fw_title = mapping["framework_title"]
    lines: list[tuple[str, int]] = []  # (text, size)

    def line(text, size=10, gap=False):
        lines.append((text, size))
        if gap:
            lines.append(("", 6))

    line(f"{org} — {fw_title}", 16)
    line(f"Framework: {framework}    Generated: {generated_at}    Author: {author}")
    line(f"Compliance: {mapping['compliance_pct']}% controls passing   "
         f"PASS={mapping['counts']['PASS']} FAIL={mapping['counts']['FAIL']} "
         f"PARTIAL={mapping['counts']['PARTIAL']} NO_EVIDENCE={mapping['counts']['NO_EVIDENCE']}", 11)
    line(f"Document signature (HMAC-SHA256): {signature[:32]}…", 8, gap=True)

    line("Control coverage and evidence", 13, gap=True)
    for row in mapping["control_rows"]:
        line(f"[{row['status']:>11}] {row['control']:<10} {row['title']}", 10)
        for ev in row["evidence"][:3]:
            line(f"        - ({ev.get('status','?')}) {ev.get('id','')}: {ev.get('title','')[:90]}", 8)
        if not row["evidence"]:
            line("        - (no evidence collected)", 8)

    # paginate at ~46 text lines per page
    pages: list[list[tuple[str, int]]] = []
    per_page = 46
    for i in range(0, len(lines), per_page):
        pages.append(lines[i:i + per_page])

    return _build_pdf(pages, title=fw_title, author=author)


def _build_pdf(pages: list[list[tuple[str, int]]], *, title: str, author: str) -> bytes:
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    # placeholder ids for catalog/pages (allocate in order)
    catalog_id = 1
    pages_id = 2
    font_id = 3
    # page + content objects
    page_ids = []
    content_ids = []
    next_id = 4
    for _ in pages:
        page_ids.append(next_id); content_ids.append(next_id + 1); next_id += 2

    def stream_obj(data: bytes) -> bytes:
        comp = zlib.compress(data)
        return (b"<< /Length " + str(len(comp)).encode() + b" /Filter /FlateDecode >>\nstream\n"
                + comp + b"\nendstream")

    # fonts
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")                                   # 1
    kids = b" ".join(f"{pid} 0 R".encode() for pid in page_ids)
    objects.append(b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(pages)).encode()
                   + b" /MediaBox [0 0 612 792] >>")                                        # 2
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")               # 3

    for idx, text_lines in enumerate(pages):
        pid, cid = page_ids[idx], content_ids[idx]
        content = _page_content(text_lines)
        objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       b"/Resources << /Font << /F1 3 0 R >> >> /Contents "
                       + f"{cid} 0 R".encode() + b" >>")                                    # page
        objects.append(stream_obj(content.encode("latin-1", "replace")))                   # content

    # assemble
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (b"trailer\n<< /Size " + str(len(objects)+1).encode() + b" /Root 1 0 R >>\n"
            b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n")
    return bytes(out)


def _page_content(text_lines: list[tuple[str, int]]) -> str:
    y = 740
    ops = ["BT"]
    for text, size in text_lines:
        ops.append(f"/F1 {size} Tf")
        ops.append(f"1 0 0 1 54 {y} Tm")
        # text matrix resets x; use Tj
        ops.append(f"({_esc(text)}) Tj")
        y -= max(14, size + 4)
        if y < 60:
            break
    ops.append("ET")
    return "\n".join(ops)

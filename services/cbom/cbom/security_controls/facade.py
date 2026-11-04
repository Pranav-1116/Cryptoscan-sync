"""HSM, KMS, PKI and the passive network path — the same six verbs, over existing collectors.

Guide 181 named these four as *deferred*, and that was honest: the platform already reads them
(`cbom.hsm_pkcs11`, `cbom.kms_collectors` + `cbom.kmip`, `cbom.certificate_chain`,
`cbom.nbom_graph`), and re-collecting them here would have been the second architecture the
specification forbids. What was missing is the *shape*: those modules produce assessments, and
the control layer consumes six-verb records.

So this module is a **facade**, not a collector. Each class parses nothing, decides nothing and
duplicates no rule: it calls the existing function and translates its answer into assets,
crypto metadata, relationships, events and health. Delete this file and no analysis is lost —
which is the test for whether a facade is a facade.

What the facades keep from the rest of the layer:

* **no key material, ever.** The KMS and HSM rows are scrubbed like any other, and a row that
  carries something shaped like material is refused by name — the existing modules already
  refuse it, and this adds the layer's own guard rather than trusting one implementation;
* **evidence on everything.** Each row that becomes an asset or a claim gets an ``EVID-`` id
  from the shared :class:`~cbom.security_controls.base.EvidenceBook`;
* **the same fact classes.** Key metadata read from a KMS is ``CONFIGURED``; a certificate
  the platform observed on the wire is ``OBSERVED``; an assessment's inference stays
  ``INFERRED`` and never becomes a fact.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .base import CONFIGURED, OBSERVED, ControlRefused, DeviceCollector, _norm, scrub

#: the assets a facade may emit, per control. A kind outside this set is a bug in the facade,
#: caught here rather than at projection time.
KINDS: dict[str, tuple[str, ...]] = {
    "HSM": ("HSM", "HSM_CLUSTER", "HSM_PARTITION", "KEY_REFERENCE", "FIRMWARE"),
    "KMS": ("KMS", "KEY_REFERENCE"),
    "PKI": ("CERTIFICATE", "CERTIFICATE_AUTHORITY", "ALGORITHM"),
    "NETWORK": ("NETWORK_ENDPOINT", "CIPHER_SUITE", "NETWORK_SEGMENT"),
}


#: what each facade reads and what it must never read. The device packages declare the same
#: pair; a facade is not exempt for being a re-shaping, because the prohibition is about the
#: bank's keys and its customers' traffic, not about which module noticed them.
FACADE_CONTRACT: dict[str, dict[str, tuple[str, ...]]] = {
    "HSM": {
        "collects": ("model and firmware", "FIPS mode", "partition inventory",
                     "crypto capabilities", "key *labels* and attributes"),
        "must_not": ("key material", "PINs", "SO/partition passwords", "wrapped key blobs",
                     "backup files", "operator session tokens"),
    },
    "KMS": {
        "collects": ("key references", "algorithm and size", "usage and state",
                     "rotation schedule", "provider and region"),
        "must_not": ("plaintext or ciphertext key material", "data keys",
                     "import tokens", "API secrets", "grant tokens"),
    },
    "PKI": {
        "collects": ("certificates and authorities", "public key algorithm and size",
                     "validity", "chain paths", "revocation state"),
        "must_not": ("private keys", "CSR private material", "keystore passwords",
                     "CA operator credentials", "OCSP request nonces bound to a client"),
    },
    "NETWORK": {
        "collects": ("endpoints", "TLS version", "cipher suites", "SNI and ALPN",
                     "handshake outcomes", "JA3/JA3S fingerprints"),
        "must_not": ("payloads", "HTTP bodies", "cookies", "authorization headers",
                     "client certificates' private half", "session keys"),
    },
}


class FacadeCollector(DeviceCollector):
    """A collector whose analysis is an existing module's, reached through a named call."""

    #: the module and function this facade delegates to, printed in its health record so a
    #: reviewer can see the analysis is elsewhere
    delegates: tuple[str, ...] = ()

    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "facade": True,
                "delegates_to": list(self.delegates),
                "note": ("this collector re-shapes an existing module's answer; it does not "
                         "re-implement the analysis")}

    def _guard_kind(self, kind: str, name: str) -> bool:
        allowed = KINDS.get(self.control, ())
        if kind in allowed:
            return True
        self._refuse("KIND_OUTSIDE_FACADE", name,
                     f"a {self.control} facade emits {', '.join(allowed)}; {kind} came from "
                     "the delegate and is a bug in the translation, not in the model")
        return False

    def _row(self, kind: str, name: Any, *, row: Mapping[str, Any] | None = None,
             attributes: Mapping[str, Any] | None = None,
             evidence_payload: Any = None, version: Any = None,
             fact: str = CONFIGURED) -> dict[str, Any] | None:
        name_text = _norm(name)
        if not name_text or not self._guard_kind(kind, name_text):
            return None
        clean, redactions = scrub(dict(attributes or {}))
        self.redactions.extend({**item, "asset": name_text} for item in redactions)
        return {
            "kind": kind, "name": name_text, "vendor": self.spec.vendor,
            "product": self.spec.product,
            "environment": _norm((row or {}).get("environment")).upper() or "PRODUCTION",
            "version": _norm(version) or None,
            "location": _norm((row or {}).get("location")) or None,
            "attributes": {"control_type": self.control, "facade": self.spec.key,
                           **{key: value for key, value in clean.items()
                              if value not in (None, "", [], {})}},
            "fact": fact,
            "evidence_id": self.evidence.id_for(kind, name_text,
                                                evidence_payload if evidence_payload is not None
                                                else clean),
        }


# --------------------------------------------------------------------------- #
# HSM
# --------------------------------------------------------------------------- #

class HsmFacade(FacadeCollector):
    """HSM fleet: model, firmware, capabilities and *key metadata* — never key material."""

    delegates: tuple[str, ...] = ("cbom.hsm_pkcs11.assess_hsm_deep",
                                  "cbom.hsm_pkcs11.detect_vendor")

    def discover_assets(self) -> list[dict[str, Any]]:
        rows = self.feed.get("hsms") or []
        assets: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, Mapping):
                self._refuse("MALFORMED_ASSET", "(row)", "an HSM row must be a mapping")
                continue
            row = dict(raw)
            row = self._material_guard(row, row.get("asset_id") or row.get("name"))
            if row is None:
                continue
            name = _norm(row.get("asset_id") or row.get("name"))
            firmware = row.get("firmware")
            version = (firmware.get("version") if isinstance(firmware, Mapping) else firmware)
            model = _norm(row.get("model")) or None
            attrs = {
                "manufacturer": row.get("manufacturer"), "model": model,
                "device_type": row.get("device_type"),
                "serial_reference": row.get("serial_reference"),
                "firmware": version, "fips": row.get("fips"),
                "capabilities": row.get("crypto_capabilities") or row.get("capabilities"),
                "partitions": row.get("partitions"),
            }
            asset = self._row("HSM", name, row=row, attributes=attrs, version=version)
            if asset:
                assets.append(asset)
        return assets

    def collect_configuration(self) -> dict[str, Any]:
        sections: dict[str, list[dict[str, Any]]] = {}
        rows = [row for row in (self._material_guard(dict(raw), raw.get("asset_id") or
                                                    raw.get("name"))
                                for raw in (self.feed.get("hsms") or [])
                                if isinstance(raw, Mapping)) if row]
        if rows:
            sections["hsms"] = [{
                "section": "hsms", "control": self.control, "vendor": self.spec.vendor,
                "fields": {key: value for key, value in {
                    "asset_id": row.get("asset_id"), "model": row.get("model"),
                    "manufacturer": row.get("manufacturer"),
                    "firmware": (row.get("firmware") or {}).get("version")
                    if isinstance(row.get("firmware"), Mapping) else row.get("firmware"),
                    "slots": len(row.get("partitions") or []),
                }.items() if value not in (None, "")},
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("CONFIG:HSM", row.get("asset_id"), row),
            } for row in rows]
        return {"control": self.control, "vendor": self.spec.vendor, "adapter": self.spec.key,
                "sections": sections, "redactions": self.redactions, "fact": CONFIGURED}

    def collect_crypto_metadata(self) -> list[dict[str, Any]]:
        """PQC readiness and firmware, from the existing assessment — as metadata."""
        from cbom import hsm_pkcs11

        rows = [row for row in (self._material_guard(dict(raw), raw.get("asset_id") or
                                                    raw.get("name"))
                                for raw in (self.feed.get("hsms") or [])
                                if isinstance(raw, Mapping)) if row]
        if not rows:
            return []
        try:
            assessed = hsm_pkcs11.assess_hsm_deep(rows)
        except Exception as exc:  # noqa: BLE001 — a delegate failure is a health finding
            self._refuse("DELEGATE_FAILED", "cbom.hsm_pkcs11.assess_hsm_deep",
                         f"{type(exc).__name__}: {exc}")
            return []
        crypto: list[dict[str, Any]] = []
        for row in assessed.get("hsms") or assessed.get("rows") or []:
            asset = _norm(row.get("asset_id") or row.get("name"))
            pqc = row.get("pqc") if isinstance(row.get("pqc"), Mapping) else {}
            facts = {
                "pqc_status": pqc.get("pqc_status") or row.get("pqc_status"),
                "firmware": row.get("firmware"), "fips": row.get("fips"),
                "algorithms": row.get("algorithms"),
            }
            crypto.append({
                "asset": asset, "control": self.control, "vendor": self.spec.vendor,
                "tls_version": None, "cipher_suites": [],
                "key_exchange": None, "certificate": None, "sni": None, "alpn": None,
                "capabilities": {key: value for key, value in facts.items()
                                 if value not in (None, "", [], {})},
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("CRYPTO:HSM", asset, facts),
            })
        return crypto

    def _material_guard(self, row: dict[str, Any], subject: Any) -> dict[str, Any] | None:
        material = [key for key in row if "key_material" in str(key).lower()
                    or "private_key" in str(key).lower() or str(key).lower() == "keyblob"]
        if material:
            self._refuse("KEY_MATERIAL_REFUSED", subject,
                         f"the row carries {', '.join(material)}; an HSM read keeps key "
                         "metadata and never key material, so the row is dropped")
            return None
        return row


# --------------------------------------------------------------------------- #
# KMS
# --------------------------------------------------------------------------- #

class KmsFacade(FacadeCollector):
    """KMS key inventory: algorithm, size, usage and state. Never the key."""

    delegates: tuple[str, ...] = ("cbom.kms_collectors.key_records_from_kms",
                                  "cbom.kms_collectors.posture",
                                  "cbom.usage_evidence.key_metadata")

    def _records(self) -> dict[str, Any]:
        from cbom import kms_collectors

        try:
            return kms_collectors.key_records_from_kms(self.feed.get("keys") or [])
        except Exception as exc:  # noqa: BLE001
            self._refuse("DELEGATE_FAILED", "cbom.kms_collectors.key_records_from_kms",
                         f"{type(exc).__name__}: {exc}")
            return {"records": [], "refused": []}

    def discover_assets(self) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []
        providers = {_norm(row.get("provider")) for row in self.feed.get("keys") or []
                     if isinstance(row, Mapping) and row.get("provider")}
        for provider in sorted(name for name in providers if name):
            asset = self._row("KMS", provider, attributes={"provider": provider})
            if asset:
                assets.append(asset)
        for record in self._records().get("records") or []:
            asset = self._row(
                "KEY_REFERENCE", record.get("key_ref"),
                attributes={key: record.get(key) for key in
                            ("provider", "algorithm", "size", "usage", "status",
                             "created_at", "rotation")},
                evidence_payload={key: record.get(key) for key in
                                  ("provider", "algorithm", "size", "usage", "status")},
                fact=CONFIGURED)
            if asset:
                assets.append(asset)
        for refused in self._records().get("refused") or []:
            self._refuse("KEY_ROW_REFUSED", refused.get("key_ref") or "(row)",
                         refused.get("reason") or "the KMS module refused the row")
        return assets

    def collect_configuration(self) -> dict[str, Any]:
        return {"control": self.control, "vendor": self.spec.vendor, "adapter": self.spec.key,
                "sections": {}, "redactions": self.redactions, "fact": CONFIGURED}

    def collect_crypto_metadata(self) -> list[dict[str, Any]]:
        crypto: list[dict[str, Any]] = []
        for record in self._records().get("records") or []:
            facts = {key: record.get(key) for key in
                     ("algorithm", "size", "usage", "status", "provider")}
            crypto.append({
                "asset": _norm(record.get("key_ref")), "control": self.control,
                "vendor": self.spec.vendor, "tls_version": None, "cipher_suites": [],
                "key_exchange": None, "certificate": None, "sni": None, "alpn": None,
                "capabilities": {key: value for key, value in facts.items()
                                 if value not in (None, "", [], {})},
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("CRYPTO:KEY", record.get("key_ref"), facts),
            })
        return crypto

    def collect_relationships(self) -> list[dict[str, Any]]:
        """``KMS HOLDS_KEY KEY_REFERENCE`` — the one claim this facade can state."""
        claims: list[dict[str, Any]] = []
        provider_of = {_norm(record.get("key_ref")): _norm(record.get("provider"))
                       for record in self._records().get("records") or []}
        for key_ref, provider in sorted(provider_of.items()):
            if not key_ref or not provider:
                continue
            crypto = next((row for row in self.collect_crypto_metadata()
                           if row["asset"] == key_ref), None)
            claims.append({
                "from": provider, "relation": "HOLDS_KEY", "to": key_ref,
                "basis": "api-poll", "fact": CONFIGURED,
                "confidence": CONFIGURED,
                "evidence_ids": [crypto["evidence_id"]] if crypto else
                                [self.evidence.id_for("KEY", key_ref, provider)],
                "facts": {"provider": provider},
            })
        return claims


# --------------------------------------------------------------------------- #
# PKI
# --------------------------------------------------------------------------- #

class PkiFacade(FacadeCollector):
    """Certificates and authorities: algorithms, sizes, validity and chains."""

    delegates: tuple[str, ...] = ("cbom.certificate_chain.certificate",
                                  "cbom.certificate_chain.chain")

    def _certificate_rows(self) -> list[dict[str, Any]]:
        """The feed's certificates, each carrying *this* snapshot's evidence id.

        ``certificate_chain.certificate`` refuses a row it cannot cite, and it is right to:
        a chain hop with no evidence id is an assertion. The id belongs to this facade
        because this facade is what read the row, so an id the feed carries from somewhere
        else is overwritten rather than borrowed — borrowing would cite a document this
        snapshot does not contain.
        """
        rows: list[dict[str, Any]] = []
        for raw in self.feed.get("certificates") or []:
            if not isinstance(raw, Mapping):
                self._refuse("MALFORMED_ASSET", "(row)", "a certificate row must be a mapping")
                continue
            row = dict(raw)
            # the delegate's own field names: ``ref`` → ``certificate_ref``,
            # ``fingerprint`` → ``fingerprint_sha256``. Renaming here keeps the delegate's
            # identity rules (and its refusals) in one place instead of two.
            if not row.get("certificate_ref"):
                for alias in ("ref", "name", "id"):
                    if row.get(alias):
                        row["certificate_ref"] = _norm(row[alias])
                        break
            if not row.get("fingerprint_sha256") and row.get("fingerprint"):
                row["fingerprint_sha256"] = _norm(row["fingerprint"])
            if not row.get("key_size") and row.get("public_key_size"):
                row["key_size"] = row["public_key_size"]
            row["evidence_id"] = self.evidence.id_for(
                "CERTIFICATE", row.get("certificate_ref") or row.get("subject")
                or row.get("fingerprint_sha256"), row)
            rows.append(row)
        return rows

    def _chain(self) -> dict[str, Any]:
        from cbom import certificate_chain

        try:
            return certificate_chain.chain(
                self._certificate_rows(),
                anchors=self.feed.get("anchors") or (),
                # ``declared`` is the caller's own statement that ref X is issued by key id Y,
                # for a PKI whose export names issuers by neither DN nor extension. It is
                # passed through untouched: the facade assembles nothing the feed did not say.
                declared=self.feed.get("declared") or None)
        except Exception as exc:  # noqa: BLE001
            self._refuse("DELEGATE_FAILED", "cbom.certificate_chain.chain",
                         f"{type(exc).__name__}: {exc}")
            return {"certificates": [], "refused": []}

    def discover_assets(self) -> list[dict[str, Any]]:
        body = self._chain()
        assets: list[dict[str, Any]] = []
        for row in _certificate_records(body):
            name = _norm(row.get("certificate_ref") or row.get("ref") or row.get("subject"))
            kind = "CERTIFICATE_AUTHORITY" if row.get("is_ca") or row.get("kind") == "CA" \
                else "CERTIFICATE"
            public_key = row.get("public_key") if isinstance(row.get("public_key"), Mapping) \
                else {}
            asset = self._row(kind, name, attributes={
                "subject": row.get("subject"), "issuer": row.get("issuer"),
                "serial": row.get("serial"), "state": row.get("state"),
                "public_key_algorithm": row.get("public_key_algorithm")
                or public_key.get("algorithm"),
                "public_key_size": row.get("public_key_size") or public_key.get("key_size"),
                "not_before": row.get("not_before"), "not_after": row.get("not_after"),
                "self_signed": row.get("self_signed"), "revoked": row.get("revoked"),
                "problems": [problem.get("kind") for problem in row.get("problems") or []
                             if isinstance(problem, Mapping)],
            }, evidence_payload={key: row.get(key) for key in
                                 ("subject", "issuer", "not_after", "state")},
                version=None)
            if asset:
                assets.append(asset)
        for refused in body.get("refused") or []:
            self._refuse("CERTIFICATE_REFUSED", (refused.get("certificate") or {}).get("ref")
                         if isinstance(refused.get("certificate"), Mapping) else "(row)",
                         refused.get("reason") or "the chain module refused the record")
        return assets

    def collect_configuration(self) -> dict[str, Any]:
        return {"control": self.control, "vendor": self.spec.vendor, "adapter": self.spec.key,
                "sections": {}, "redactions": self.redactions, "fact": CONFIGURED}

    def collect_crypto_metadata(self) -> list[dict[str, Any]]:
        crypto: list[dict[str, Any]] = []
        for row in _certificate_records(self._chain()):
            name = _norm(row.get("certificate_ref") or row.get("subject"))
            public_key = row.get("public_key") if isinstance(row.get("public_key"), Mapping) \
                else {}
            facts = {"public_key_algorithm": row.get("public_key_algorithm")
                     or public_key.get("algorithm"),
                     "public_key_size": row.get("public_key_size")
                     or public_key.get("key_size"),
                     "signature_algorithm": row.get("signature_algorithm"),
                     "not_after": row.get("not_after"), "expired": row.get("expired")}
            crypto.append({
                "asset": name, "control": self.control, "vendor": self.spec.vendor,
                "tls_version": None, "cipher_suites": [], "key_exchange": None,
                "certificate": {key: value for key, value in facts.items()
                                if value not in (None, "", [])},
                "sni": None, "alpn": None, "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("CRYPTO:CERTIFICATE", name, facts),
            })
        return crypto

    def collect_relationships(self) -> list[dict[str, Any]]:
        """Each resolved path → one claim per hop, in the model's own relations.

        ``path`` holds ``[leaf, issuer, …, anchor]``. A hop out of a leaf is
        ``CERTIFICATE ISSUED_BY CERTIFICATE_AUTHORITY``; a hop between two authorities is
        ``SIGNED_BY``. Both are the vocabulary's relations — nothing here invents an edge, and
        an unresolved path yields no claim at all rather than a hopeful one.
        """
        claims: list[dict[str, Any]] = []
        body = self._chain()
        certificates = body.get("certificates") if isinstance(body.get("certificates"),
                                                              Mapping) else {}
        for path in body.get("paths") or []:
            if not isinstance(path, Mapping):
                continue
            hops = [hop for hop in path.get("path") or [] if isinstance(hop, Mapping)]
            for parent, child in zip(hops, hops[1:]):
                subject = _norm(parent.get("certificate_ref"))
                issuer = _norm(child.get("certificate_ref"))
                if not subject or not issuer:
                    continue
                parent_record = certificates.get(subject) or {}
                relation = "SIGNED_BY" if parent_record.get("is_ca") else "ISSUED_BY"
                claims.append({
                    "from": subject, "relation": relation, "to": issuer,
                    "basis": "config-parse", "fact": CONFIGURED,
                    "evidence_ids": [self.evidence.id_for(
                        "CHAIN", f"{subject}->{issuer}",
                        {"path": path.get("certificate_ref"), "depth": path.get("depth")})],
                    "facts": {"path": path.get("certificate_ref"),
                              "resolution": path.get("resolution"),
                              "anchor": path.get("anchor")},
                })
        return claims


# --------------------------------------------------------------------------- #
# Network (passive)
# --------------------------------------------------------------------------- #

class NetworkFacade(FacadeCollector):
    """Observed endpoints and the TLS they negotiated — the passive path, as six verbs."""

    delegates: tuple[str, ...] = ("cbom.nbom_graph.endpoint", "cbom.nbom_graph.estate")

    def discover_assets(self) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []
        for row in self.feed.get("endpoints") or []:
            if not isinstance(row, Mapping):
                self._refuse("MALFORMED_ASSET", "(row)", "an endpoint row must be a mapping")
                continue
            host = _norm(row.get("host"))
            port = row.get("port")
            name = f"{host}:{port}" if host and port else host
            asset = self._row("NETWORK_ENDPOINT", name, attributes={
                "host": host, "port": port, "protocol": row.get("protocol") or "TCP",
                "observed": bool(row.get("observed", True)),
                "sni": row.get("sni"), "alpn": row.get("alpn"),
                "source": row.get("source") or "passive",
            }, evidence_payload={key: row.get(key) for key in
                                 ("host", "port", "protocol", "sni", "tls_version")},
                fact=OBSERVED)
            if asset:
                assets.append(asset)
        return assets

    def collect_configuration(self) -> dict[str, Any]:
        return {"control": self.control, "vendor": self.spec.vendor, "adapter": self.spec.key,
                "sections": {}, "redactions": self.redactions, "fact": CONFIGURED}

    def collect_crypto_metadata(self) -> list[dict[str, Any]]:
        crypto: list[dict[str, Any]] = []
        for row in self.feed.get("endpoints") or []:
            if not isinstance(row, Mapping):
                continue
            host, port = _norm(row.get("host")), row.get("port")
            name = f"{host}:{port}" if host and port else host
            facts = {"tls_version": row.get("tls_version"),
                     "cipher_suites": list(row.get("cipher_suites") or []),
                     "sni": row.get("sni"), "alpn": row.get("alpn")}
            if not any(value not in (None, "", []) for value in facts.values()):
                continue
            crypto.append({
                "asset": name, "control": self.control, "vendor": self.spec.vendor,
                "tls_version": facts["tls_version"], "cipher_suites": facts["cipher_suites"],
                "key_exchange": row.get("key_exchange"),
                "certificate": row.get("certificate"), "sni": facts["sni"],
                "alpn": facts["alpn"], "fact": OBSERVED,
                "evidence_id": self.evidence.id_for("CRYPTO:ENDPOINT", name, facts),
            })
        return crypto

    def collect_security_events(self) -> list[dict[str, Any]]:
        """A handshake that failed, or a downgrade seen on the wire, is an event."""
        events: list[dict[str, Any]] = []
        for row in self.feed.get("events") or []:
            if not isinstance(row, Mapping):
                continue
            kind = _norm(row.get("kind") or "HANDSHAKE").upper()
            if kind not in {"HANDSHAKE", "ALERT", "DOWNGRADE"}:
                self._refuse("UNDECLARED_EVENT_KIND", kind,
                             f"{self.spec.key} declares HANDSHAKE, ALERT, DOWNGRADE")
                continue
            clean, redactions = scrub(dict(row))
            self.redactions.extend(redactions)
            # an event is a moment on the wire, not a copy of it: only the fields that name
            # the handshake travel, and every other field is recorded as *not collected*
            # rather than carried. A body, a cookie or an auth header that reached a sensor
            # stops here.
            kept = {key: value for key, value in clean.items() if key in NETWORK_EVENT_FIELDS}
            dropped = sorted(set(clean) - set(kept))
            self.redactions.extend(
                {"field": key, "rule": "FIELD_NOT_COLLECTED", "event": kind,
                 "reason": "an observed event carries handshake metadata and never a "
                           "payload, header or body"}
                for key in dropped if key not in NETWORK_EVENT_FIELDS)
            clean = kept
            events.append({
                "kind": kind, "control": self.control, "vendor": self.spec.vendor,
                "signature": None, "signature_revision": None,
                "action": _norm(clean.get("action")).upper() or None,
                "src": _norm(clean.get("src")) or None, "dst": _norm(clean.get("dst")) or None,
                "protocol": _norm(clean.get("protocol")) or None,
                "port": clean.get("port"), "tls_version": clean.get("tls_version"),
                "cipher_suite": clean.get("cipher_suite"), "sni": clean.get("sni"),
                "timestamp": _norm(clean.get("timestamp")) or None,
                "fact": OBSERVED,
                "evidence_id": self.evidence.id_for("EVENT:HANDSHAKE",
                                                    clean.get("timestamp"), clean),
                "metadata": clean,
            })
        return events


#: the only fields an observed network event may carry. Anything else a sensor saw — a body,
#: a header, a cookie — is dropped by name, because a collector that forwards a request to
#: answer "was this handshake weak?" has copied the bank's traffic into an inventory.
NETWORK_EVENT_FIELDS: frozenset[str] = frozenset({
    "kind", "src", "dst", "src_port", "dst_port", "port", "protocol", "action", "timestamp",
    "at", "tls_version", "cipher_suite", "sni", "alpn", "alert", "downgrade_from",
    "downgrade_to", "handshake_state", "ja3", "ja3s", "evidence_id",
})


FACADES: dict[str, Callable[..., FacadeCollector]] = {
    "HSM": HsmFacade,
    "KMS": KmsFacade,
    "PKI": PkiFacade,
    "NETWORK": NetworkFacade,
}


def _certificate_records(body: Mapping[str, Any]) -> list[dict[str, Any]]:
    """``certificate_chain.chain`` returns ``certificates`` keyed by ref, not a list."""
    certificates = body.get("certificates")
    if isinstance(certificates, Mapping):
        return [dict(value) for value in certificates.values() if isinstance(value, Mapping)]
    return [dict(row) for row in certificates or () if isinstance(row, Mapping)]


def facade_spec(control: str) -> Any:
    """The synthetic adapter spec a facade registers under.

    A facade has no vendor dialect of its own: it reads what another collector already read.
    The spec says exactly that, in ``notes``, so the catalogue cannot present it as a new
    integration.
    """
    from .base import AdapterSpec

    control_text = _norm(control).upper()
    if control_text not in FACADES:
        raise ControlRefused("NOT_A_FACADE",
                             f"{control_text or '(none)'} has no facade; implemented: "
                             f"{', '.join(sorted(FACADES))}")
    return AdapterSpec(
        key=f"{control_text.lower()}.existing-collectors",
        control=control_text,
        vendor="(the platform's own collectors)",
        product=f"{control_text} facade",
        operations=("QUERY", "API_GET", "READ_CONFIG_FILE", "PROBE_TLS"),
        sections={},
        endpoints=(),
        notes=("re-shapes an existing read-only collector's output into the six-verb record "
               "shape; it opens no connection of its own"),
    )

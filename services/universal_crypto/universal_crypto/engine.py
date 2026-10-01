"""§36 ZELNX CRYPTO ENGINE — deterministic end-to-end pipeline.

    SOURCE / BINARY / RUNTIME
      → AST / Binary / Runtime engines
      → Library fingerprinting
      → Protocol analysis
      → Certificate analysis
      → Crypto material metadata
      → Evidence fusion + confidence
      → CONFIRMED | UNKNOWN (→ deep analysis queue)
      → Crypto normalization
      → Live crypto state → Live CBOM → dependency graph
      → PQC classification → agility score → migration readiness
      → What-if simulator

No AI: every stage is a pure function of evidence and explicit catalogs.
"""

from __future__ import annotations

from typing import Any

from universal_crypto.agility import CryptoAgilityEngine
from universal_crypto.ast_engine import CryptoAstEngine
from universal_crypto.binary_engine import BinaryCryptoDetector, BinaryParser
from universal_crypto.certificate_intel import CertificateIntelligence
from universal_crypto.classification import (
    CryptoClassifier,
    QuantumVulnerabilityClassifier,
)
from universal_crypto.confidence import band_for, score_evidence

#: discovery source → §28 evidence kind (used for fusion scoring)
from universal_crypto.correlator import FindingCorrelator
from universal_crypto.custom_crypto import CustomCryptoClassifier
from universal_crypto.dependency_graph import CryptoDependencyGraph
from universal_crypto.discovery import UniversalDiscovery
from universal_crypto.findings import FindingBuilder
from universal_crypto.hardcoded import HardcodedCryptoDetector
from universal_crypto.key_lifecycle import KeyLifecycleAnalyzer
from universal_crypto.library_fingerprints import LibraryFingerprinter
from universal_crypto.misconfig import MisconfigurationDetector
from universal_crypto.models import (
    CryptoObservation,
    Evidence,
    EvidenceType,
)

#: discovery source → §28 evidence kind (used for fusion scoring)
_SOURCE_EVIDENCE_KIND = {
    "source_code": EvidenceType.AST,
    "binaries": EvidenceType.BINARY,
    "shared_libraries": EvidenceType.BINARY,
    "package_dependencies": EvidenceType.LIBRARY,
    "configuration": EvidenceType.CONFIG,
    "certificates": EvidenceType.CERTIFICATE,
    "keys_metadata": EvidenceType.CONFIG,
    "trust_stores": EvidenceType.CERTIFICATE,
    "network_protocols": EvidenceType.PROTOCOL,
    "tls_endpoints": EvidenceType.PROTOCOL,
    "ssh": EvidenceType.PROTOCOL,
    "ipsec": EvidenceType.PROTOCOL,
    "vpn": EvidenceType.PROTOCOL,
    "runtime": EvidenceType.RUNTIME,
    "libraries": EvidenceType.LIBRARY,
    "hardcoded_scan": EvidenceType.CONFIG,
    "randomness_scan": EvidenceType.RUNTIME,
    "custom_crypto": EvidenceType.BINARY,
    "key_metadata": EvidenceType.CONFIG,
}
from universal_crypto.pqc_readiness import PqcReadinessEngine
from universal_crypto.protocol_engine import (
    IpsecAnalysis,
    SshAnalysis,
    TlsAnalysis,
)
from universal_crypto.randomness import RandomnessAnalyzer
from universal_crypto.registry import find as registry_find
from universal_crypto.runtime_engine import RuntimeCryptoEngine
from universal_crypto.simulator import MigrationSimulator
from universal_crypto.unknown_detector import UnknownCryptoDetector
from universal_crypto.weak_crypto import WeakCryptoClassifier


class UniversalCryptoEngine:
    """The §36 orchestrator. Deterministic; no AI anywhere."""

    def __init__(self) -> None:
        self.discovery = UniversalDiscovery()
        self.ast = CryptoAstEngine()
        self.binary_parser = BinaryParser()
        self.binary = BinaryCryptoDetector()
        self.runtime = RuntimeCryptoEngine()
        self.fingerprinter = LibraryFingerprinter()
        self.tls = TlsAnalysis()
        self.ssh = SshAnalysis()
        self.ipsec = IpsecAnalysis()
        self.certs = CertificateIntelligence()
        self.classifier = CryptoClassifier()
        self.quantum = QuantumVulnerabilityClassifier()
        self.pqc = PqcReadinessEngine()
        self.agility = CryptoAgilityEngine()
        self.hardcoded = HardcodedCryptoDetector()
        self.weak = WeakCryptoClassifier()
        self.misconfig = MisconfigurationDetector()
        self.custom = CustomCryptoClassifier()
        self.randomness = RandomnessAnalyzer()
        self.key_lifecycle = KeyLifecycleAnalyzer()
        self.correlator = FindingCorrelator()
        self.unknown = UnknownCryptoDetector()
        self.finding_builder = FindingBuilder()
        self.simulator = MigrationSimulator()

    # ------------------------------------------------------------------ #
    # §1/§36 scan
    # ------------------------------------------------------------------ #

    def scan(self, inputs: dict[str, Any]) -> dict[str, Any]:
        """Run the full pipeline over one scan input bundle.

        Input bundle keys (all optional):
          sources:           §1 source bundles (see discovery.py)
          source_code:       [{language, text, asset_id, location}]
          binaries:          [{name, data(base64|bytes), asset_id}]
          runtime:           [{process, loaded_libraries, api_calls, ...}]
          tls:               [{suite|server_hello_hex, ...}]
          ssh:               [{host_key, kex, ciphers, ...}]
          ipsec:             [{ike_version, encryption, ...}]
          certificates:      [{der_b64, location, ...}] or PEM strings
          key_metadata:      [metadata records]
          trust_store:       [{store_name, anchors}]
          hardcoded_scan:    [{language, text}]
          randomness_scan:   [{language, text}]
          policy:            "NIST" | "FIPS" | ... (default NIST)
        """
        policy = str(inputs.get("policy") or "NIST")
        drafts: list[dict[str, Any]] = []
        assets: set[str] = set()
        binary_library_results: list[dict[str, Any]] = []
        runtime_library_results: list[dict[str, Any]] = []

        # §1 discovery + correlation
        if inputs.get("sources"):
            self.discovery.discover(inputs["sources"])
            drafts.extend(self.discovery.correlate())

        # §4/§5 AST semantic detection
        for code in inputs.get("source_code") or []:
            results = self.ast.detect_file(
                language=code.get("language", "python"),
                text=code.get("text", ""),
                asset_id=code.get("asset_id", "default"),
                location=code.get("location", ""))
            drafts.extend(results)
            assets.add(code.get("asset_id", "default"))

        # §7 binary detection
        for binary in inputs.get("binaries") or []:
            data = binary.get("data")
            if isinstance(data, str):  # base64
                import base64
                data = base64.b64decode(data)
            artifact = self.binary_parser.parse(data or b"", path=binary.get("name", ""))
            analysis = self.binary.analyze(artifact)
            from universal_crypto.binary_engine import IMPLEMENTATION_FINGERPRINTS

            for detection in analysis.get("detections", []):
                name = str(detection.get("algorithm") or "")
                detail = "; ".join(e["detail"] for e in detection.get("evidence") or [])
                asset_id = binary.get("asset_id", "default")
                location = binary.get("name", "")
                if name in IMPLEMENTATION_FINGERPRINTS:
                    # A library name is implementation evidence, not an
                    # algorithm. Keeping it out of algorithm observations avoids
                    # false findings such as an "OpenSSL" algorithm and lets the
                    # report express the weaker string-only verdict honestly.
                    binary_library_results.append({
                        "library": name,
                        "provider": name,
                        "version": "",
                        "evidence_classes": ["binary"],
                        "verdict": detection.get("verdict", "POSSIBLE_CRYPTO"),
                        "confidence": float(detection.get("best_level") or 0),
                        "asset_id": asset_id,
                        "location": location,
                        "evidence": detail,
                    })
                    continue
                drafts.append({
                    "algorithm": name,
                    "asset_id": asset_id,
                    "location": location,
                    "source": "binaries",
                    "detail": detail,
                    "evidence": [Evidence(
                        kind=EvidenceType.BINARY,
                        detail=detail,
                        location=location)],
                })
            assets.add(binary.get("asset_id", "default"))

        # §9 runtime observation
        runtime_obs: list[dict[str, Any]] = []
        for process in inputs.get("runtime") or []:
            observed = self.runtime.observe(
                process=process.get("process", "?"),
                loaded_libraries=process.get("loaded_libraries"),
                api_calls=process.get("api_calls"),
                connections=process.get("connections"),
                asset_id=process.get("asset_id", "default"))
            runtime_obs.extend(observed)
            assets.add(process.get("asset_id", "default"))
            seen_runtime_libraries: set[tuple[str, str, bool]] = set()
            for runtime in observed:
                if not runtime.library:
                    continue
                identity = (runtime.library, runtime.asset_id, bool(runtime.usage))
                if identity in seen_runtime_libraries:
                    continue
                seen_runtime_libraries.add(identity)
                runtime_library_results.append({
                    "library": runtime.library,
                    "provider": runtime.library,
                    "version": "",
                    "evidence_classes": ["runtime_api" if runtime.usage
                                         else "runtime_loaded_library"],
                    "verdict": "OBSERVED_RUNTIME",
                    "usage": bool(runtime.usage),
                    "asset_id": runtime.asset_id,
                    "location": runtime.process,
                })

        # §10/§11/§12 protocol analysis
        for tls in inputs.get("tls") or []:
            if tls.get("server_hello_hex"):
                parsed = self.tls.parse_server_hello(bytes.fromhex(tls["server_hello_hex"]))
                if parsed.get("analysis"):
                    analysis = parsed["analysis"]
                    drafts.append({
                        "algorithm": analysis["cipher"], "protocol": "TLS",
                        "asset_id": tls.get("asset_id", "default"),
                        "location": tls.get("endpoint", ""),
                        "source": "tls_endpoints",
                        "detail": f"TLS suite {analysis['suite']}",
                        "evidence": [Evidence(
                            kind=EvidenceType.PROTOCOL,
                            detail=f"TLS {analysis['suite']} "
                                   f"({analysis['key_exchange']}/{analysis['cipher']})",
                            location=tls.get("endpoint", ""))],
                    })
            elif tls.get("suite"):
                analysis = self.tls.analyze_suite(tls["suite"])
                if analysis.get("known"):
                    drafts.append({
                        "algorithm": analysis["cipher"], "protocol": "TLS",
                        "asset_id": tls.get("asset_id", "default"),
                        "location": tls.get("endpoint", ""),
                        "source": "tls_endpoints",
                        "detail": analysis["suite"],
                        "evidence": [Evidence(
                            kind=EvidenceType.PROTOCOL,
                            detail=analysis["suite"], location=tls.get("endpoint", ""))],
                    })
        for ssh in inputs.get("ssh") or []:
            analysis = self.ssh.analyze(
                host_key=ssh.get("host_key", ""), kex=ssh.get("kex", ""),
                ciphers=ssh.get("ciphers"), macs=ssh.get("macs"),
                signature_algorithms=ssh.get("signature_algorithms"))
            for obs in analysis["observations"]:
                if obs["algorithm"] != "UNKNOWN":
                    drafts.append({
                        "algorithm": obs["algorithm"], "protocol": "SSH",
                        "asset_id": ssh.get("asset_id", "default"),
                        "location": ssh.get("host", ""),
                        "source": "ssh",
                        "detail": f"SSH {obs['role']} {obs['value']}",
                        "evidence": [Evidence(
                            kind=EvidenceType.PROTOCOL,
                            detail=f"SSH {obs['role']} {obs['value']}",
                            location=ssh.get("host", ""))],
                    })
        for ipsec in inputs.get("ipsec") or []:
            analysis = self.ipsec.analyze(
                ike_version=ipsec.get("ike_version", "IKEv2"),
                encryption=ipsec.get("encryption", ""),
                integrity=ipsec.get("integrity", ""),
                dh_group=ipsec.get("dh_group", ""),
                authentication=ipsec.get("authentication", ""),
                pfs=bool(ipsec.get("pfs", False)))
            for field in ("encryption", "integrity", "dh_group", "authentication"):
                value = analysis[field]
                if value["algorithm"] != "UNKNOWN":
                    drafts.append({
                        "algorithm": value["algorithm"], "protocol": "IPsec",
                        "asset_id": ipsec.get("asset_id", "default"),
                        "location": ipsec.get("gateway", ""),
                        "source": "ipsec",
                        "detail": f"IPsec {field} {value['value']}",
                        "evidence": [Evidence(
                            kind=EvidenceType.PROTOCOL,
                            detail=f"IPsec {field} {value['value']}",
                            location=ipsec.get("gateway", ""))],
                    })

        # §13/§14/§15 certificates, key metadata, trust stores
        cert_results: list[dict[str, Any]] = []
        for cert in inputs.get("certificates") or []:
            der = cert.get("der")
            if der is None and cert.get("pem"):
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                der = x509.load_pem_x509_certificate(
                    cert["pem"].encode()).public_bytes(serialization.Encoding.DER)
            if der is not None:
                result = self.certs.analyze_certificate(
                    der=der if isinstance(der, bytes) else bytes.fromhex(der),
                    location=cert.get("location", ""),
                    asset_id=cert.get("asset_id", "default"),
                    trust_anchor=bool(cert.get("trust_anchor", False)))
                cert_results.append(result)
                key_alg = result.get("public_key_algorithm")
                if key_alg and key_alg != "UNKNOWN":
                    drafts.append({
                        "algorithm": key_alg, "protocol": "TLS",
                        "asset_id": cert.get("asset_id", "default"),
                        "location": cert.get("location", ""),
                        "source": "certificates",
                        "key_size": result.get("key_size"),
                        "curve": result.get("curve"),
                        "detail": f"certificate public key {key_alg}",
                        "evidence": [Evidence(
                            kind=EvidenceType.CERTIFICATE,
                            detail=f"cert {result.get('subject', '')} "
                                   f"{key_alg} {result.get('key_size', '')}",
                            location=cert.get("location", ""))],
                    })
                sig_alg = result.get("signature_algorithm")
                if sig_alg and sig_alg != "UNKNOWN":
                    drafts.append({
                        "algorithm": sig_alg, "protocol": "TLS",
                        "asset_id": cert.get("asset_id", "default"),
                        "location": cert.get("location", ""),
                        "source": "certificates",
                        "detail": f"certificate signature {sig_alg}",
                        "evidence": [Evidence(
                            kind=EvidenceType.CERTIFICATE,
                            detail=f"signature {sig_alg}", location=cert.get("location", ""))],
                    })
        key_metadata_results = [
            self.certs.analyze_key_metadata(record)
            for record in inputs.get("key_metadata") or []]
        trust_results = [
            self.certs.analyze_trust_store(
                store_name=store.get("store_name", "?"),
                anchors=store.get("anchors", []),
                expected_roots=store.get("expected_roots"))
            for store in inputs.get("trust_store") or []]

        # §6/§8 library fingerprinting. Binary implementation detections
        # already carry their evidence; source/dependency library inputs use
        # the multi-class fingerprinter below.
        library_results: list[dict[str, Any]] = [
            *binary_library_results, *runtime_library_results]
        for lib in inputs.get("libraries") or []:
            assets.add(lib.get("asset_id", "default"))
            res = self.fingerprinter.fingerprint(
                imports=lib.get("imports"), symbols=lib.get("symbols"),
                strings=lib.get("strings"),
                constants=[bytes.fromhex(c) if isinstance(c, str) else c
                           for c in (lib.get("constants") or [])],
                apis=lib.get("apis"), dependencies=lib.get("dependencies"))
            for result in res:
                result = dict(result)
                result["asset_id"] = lib.get("asset_id", "default")
                result["location"] = lib.get("location", "")
                library_results.append(result)
                # Library identity is not an algorithm observation. It remains
                # in the library inventory and dependency graph inputs, while
                # only algorithm-level evidence becomes a CryptoObservation.

        # §21/§22/§23/§25 structural scans
        hardcoded_results = [
            self.hardcoded.detect(code.get("text", "").splitlines(),
                                  asset_id=code.get("asset_id", "default"),
                                  location=code.get("location", ""))
            for code in inputs.get("hardcoded_scan") or []]
        randomness_results = [
            self.randomness.analyze(code.get("text", "").splitlines(),
                                    asset_id=code.get("asset_id", "default"),
                                    location=code.get("location", ""))
            for code in inputs.get("randomness_scan") or []]
        misconfig_results = []
        for check in inputs.get("misconfig") or []:
            misconfig_results.extend(self._run_misconfig(check))

        # §24 custom-crypto classification (extra item fields such as
        # asset_id/location are metadata, not classifier inputs)
        _CUSTOM_KWARGS = ("implementation_name", "symbols", "library_hint",
                          "api_names")
        custom_results = [
            self.custom.classify(**{k: item[k] for k in _CUSTOM_KWARGS
                                    if k in item})
            for item in inputs.get("custom_crypto") or []]

        # §26 key lifecycle
        lifecycle_results = self.key_lifecycle.analyze(inputs.get("key_metadata") or [])

        # ── evidence fusion + classification ────────────────────────────
        observations = self._to_observations(drafts, runtime_obs, policy)

        # §17/§18 classification
        for obs in observations:
            obs.classification = self.classifier.classify_observation(obs)

        # §18 quantum classification
        quantum_results = {
            obs.algorithm: self.quantum.classify(
                algorithm=obs.algorithm, usage=obs.usage,
                dependency_count=len([o for o in observations
                                      if o.algorithm == obs.algorithm]) - 1)
            for obs in observations}

        # §19 readiness
        readiness_results = []
        for obs in observations:
            if obs.protocol:
                protocol = obs.protocol
            else:
                protocol = ""
            readiness_results.append(self.pqc.migration_readiness(
                algorithm=obs.algorithm, protocol=protocol,
                library=obs.library or "", hardware="",
                usage=obs.usage))

        # §20 agility
        agility_results = []
        for asset in sorted(assets) or ["default"]:
            signals = self._agility_signals(asset, hardcoded_results,
                                            inputs.get("agility_signals") or [])
            agility_results.append(self.agility.score_asset(
                asset_id=asset, signals=signals))

        # §29 findings
        findings = self.finding_builder.build_many(
            observations, quantum_classifications=quantum_results)

        # §16 dependency graph
        graph = self._build_graph(inputs, observations, libraries=library_results)

        # §31 unknown crypto detection
        unknown_items = []
        for code in inputs.get("source_code") or []:
            unknown_items.extend(self.unknown.scan_source(
                code.get("text", "").splitlines(),
                asset_id=code.get("asset_id", "default"),
                location=code.get("location", "")))
        for binary in inputs.get("binaries") or []:
            data = binary.get("data")
            if isinstance(data, str):
                import base64
                data = base64.b64decode(data)
            artifact = self.binary_parser.parse(data or b"")
            unknown_items.extend(self.unknown.scan_binary(
                artifact.all_names(), asset_id=binary.get("asset_id", "default")))

        return {
            "observations": [o.model_dump() for o in observations],
            "findings": [f.to_dict() for f in findings],
            "quantum_classifications": quantum_results,
            "readiness": readiness_results,
            "agility": agility_results,
            "certificates": cert_results,
            "key_metadata": key_metadata_results,
            "trust_stores": trust_results,
            "libraries": library_results,
            "hardcoded": hardcoded_results,
            "randomness": randomness_results,
            "misconfig": misconfig_results,
            "custom_crypto": custom_results,
            "key_lifecycle": lifecycle_results,
            "graph": graph.to_dict(),
            "unknown_crypto": unknown_items,
            "policy": policy,
        }

    # -- internals -------------------------------------------------------- #

    def _to_observations(
        self,
        drafts: list[dict[str, Any]],
        runtime_obs: list[Any],
        policy: str,
    ) -> list[CryptoObservation]:
        observations: list[CryptoObservation] = []
        by_key: dict[tuple[str, str, str], CryptoObservation] = {}
        for draft in drafts:
            evidence = list(draft.get("evidence") or [])
            if not evidence:
                # drafts without pre-attached evidence get the evidence kind
                # of the source that produced them (§28 fusion)
                evidence = [Evidence(
                    kind=_SOURCE_EVIDENCE_KIND.get(
                        draft.get("source", ""), EvidenceType.CONFIG),
                    detail=draft.get("detail", ""),
                    location=draft.get("location", ""))]
            algorithm = str(draft.get("algorithm") or "").strip()
            if not algorithm or algorithm.upper() == "UNKNOWN":
                # An unknown operation belongs in the review queue, not in the
                # known-algorithm inventory as an empty/UNKNOWN algorithm row.
                continue
            entry = registry_find(algorithm)
            canonical = entry.algorithm if entry else algorithm.upper()
            operation = draft.get("operation")
            operation_key = (operation.value if hasattr(operation, "value")
                             else str(operation or ""))
            asset_id = str(draft.get("asset_id", "default") or "default")
            key = (asset_id, canonical, operation_key)
            existing = by_key.get(key)
            if existing is not None:
                # Multiple detectors are corroborating evidence for one
                # observation. Dropping later drafts made strong binary/runtime
                # evidence disappear behind the first weak string match.
                for item in evidence:
                    signature = (item.kind.value, item.detail, item.location)
                    if not any((old.kind.value, old.detail, old.location) == signature
                               for old in existing.evidence):
                        existing.evidence.append(item)
                existing.confidence = score_evidence(existing.evidence)
                existing.band = band_for(existing.confidence)
                existing.usage = existing.usage or bool(draft.get("usage"))
                existing.capability = existing.capability or bool(draft.get("capability"))
                if not existing.library and draft.get("library"):
                    existing.library = draft["library"]
                if not existing.location and draft.get("location"):
                    existing.location = draft["location"]
                sources = existing.raw.setdefault("sources", [])
                source = draft.get("source", "")
                if source and source not in sources:
                    sources.append(source)
                continue
            score = score_evidence(evidence)
            obs = CryptoObservation(
                algorithm=canonical,
                operation=operation,
                library=draft.get("library"),
                key_size=draft.get("key_size"),
                curve=draft.get("curve"),
                padding=draft.get("padding"),
                digest=draft.get("digest"),
                protocol=draft.get("protocol"),
                asset_id=asset_id,
                location=draft.get("location", ""),
                evidence=evidence,
                confidence=score,
                band=band_for(score),
                usage=bool(draft.get("usage")),
                capability=bool(draft.get("capability")),
                source=draft.get("source", ""),
                raw=draft,
            )
            if entry is not None:
                obs.quantum_status = entry.quantum_status
            if canonical in ("TLS", "SSH", "IPsec", "QUIC"):
                obs.protocol = canonical  # protocol assets classify as PROTOCOL
            observations.append(obs)
            by_key[key] = obs
        # Runtime observations merge as usage evidence. A loaded library is
        # capability/dependency evidence only (usage=False); an exercised API
        # can create an observation even when static scanning found nothing.
        from universal_crypto.binary_engine import IMPLEMENTATION_FINGERPRINTS

        for runtime in runtime_obs:
            algorithm = str(getattr(runtime, "algorithm", "") or "").strip()
            if not algorithm or algorithm in IMPLEMENTATION_FINGERPRINTS:
                continue
            entry = registry_find(algorithm)
            canonical = entry.algorithm if entry else algorithm.upper()
            asset_id = str(getattr(runtime, "asset_id", "default") or "default")
            runtime_operation = getattr(runtime, "operation", None)
            operation_key = (runtime_operation.value
                             if hasattr(runtime_operation, "value")
                             else str(runtime_operation or ""))
            # Match on the same operation as static evidence. If runtime input
            # has no operation, it remains a separate operation-less record
            # rather than being attached to an arbitrary same-algorithm claim.
            target = by_key.get((asset_id, canonical, operation_key))
            runtime_evidence = Evidence(
                kind=EvidenceType.RUNTIME,
                detail=f"runtime {getattr(runtime, 'process', '?')} "
                       f"{getattr(runtime, 'api', '') or 'observation'}",
                location=getattr(runtime, "process", ""))
            if target is None:
                if not bool(getattr(runtime, "usage", False)):
                    continue
                target = CryptoObservation(
                    algorithm=canonical,
                    operation=runtime_operation,
                    library=getattr(runtime, "library", None),
                    protocol=getattr(runtime, "protocol", None),
                    asset_id=asset_id,
                    location=getattr(runtime, "process", ""),
                    evidence=[runtime_evidence],
                    confidence=score_evidence([runtime_evidence]),
                    band=band_for(score_evidence([runtime_evidence])),
                    usage=True,
                    source="runtime",
                )
                if entry is not None:
                    target.quantum_status = entry.quantum_status
                if canonical in ("TLS", "SSH", "IPsec", "QUIC"):
                    target.protocol = canonical
                observations.append(target)
                by_key[(asset_id, canonical, operation_key)] = target
                continue
            signature = (runtime_evidence.kind.value, runtime_evidence.detail,
                         runtime_evidence.location)
            if not any((old.kind.value, old.detail, old.location) == signature
                       for old in target.evidence):
                target.evidence.append(runtime_evidence)
            target.usage = target.usage or bool(getattr(runtime, "usage", False))
            if not target.library and getattr(runtime, "library", None):
                target.library = runtime.library
            target.confidence = score_evidence(target.evidence)
            target.band = band_for(target.confidence)
        # weak-crypto policy classification feeds `raw` context
        weak = WeakCryptoClassifier()
        for obs in observations:
            verdict = weak.classify(algorithm=obs.algorithm, policy=policy,
                                    key_size=obs.key_size)
            obs.raw["policy_verdict"] = verdict
        return observations

    def _build_graph(self, inputs: dict[str, Any],
                     observations: list[CryptoObservation],
                     libraries: list[dict[str, Any]] | None = None) -> CryptoDependencyGraph:
        graph = CryptoDependencyGraph()
        explicit_apps = [str(app) for app in inputs.get("applications") or []]
        if explicit_apps:
            apps = set(explicit_apps)
        else:
            asset_ids = {str(obs.asset_id) for obs in observations}
            asset_ids.update(str(row.get("asset_id")) for row in (libraries or [])
                             if row.get("asset_id"))
            apps = {"default-application" if asset == "default" else asset
                    for asset in asset_ids} or {"default-application"}
        library_rows = [row for row in (libraries or []) if row.get("library")]
        for app in sorted(apps):
            graph.add_node(app, kind="application")
            asset_id = "default" if app == "default-application" else app
            libs = {str(o.library) for o in observations
                    if o.library and str(o.asset_id) == asset_id}
            libs.update(str(row["library"]) for row in library_rows
                        if str(row.get("asset_id", "default")) == asset_id)
            for lib in sorted(libs):
                graph.add_node(lib, kind="crypto_library")
                graph.add_edge(app, lib, "dependsOn")
            protocols = {str(o.protocol) for o in observations
                         if o.protocol and str(o.asset_id) == asset_id}
            for protocol in sorted(protocols):
                graph.add_node(protocol, kind="protocol")
                graph.add_edge(app, protocol, "uses")
            for obs in observations:
                if str(obs.asset_id) != asset_id:
                    continue
                if obs.library:
                    graph.add_edge(obs.library, obs.algorithm, "uses")
                if obs.protocol:
                    graph.add_edge(obs.protocol, obs.algorithm, "uses")
        for cert in inputs.get("certificates") or []:
            cert_id = cert.get("location") or cert.get("name") or "certificate"
            cert_app = str(cert.get("asset_id") or "default-application")
            if cert_app == "default":
                cert_app = "default-application"
            graph.add_node(cert_id, kind="certificate")
            graph.add_edge(cert_app, cert_id, "uses")
            for obs in observations:
                if (obs.source == "certificates" and obs.protocol == "TLS"
                        and str(obs.asset_id) == ("default" if cert_app == "default-application" else cert_app)):
                    graph.add_edge(cert_id, obs.algorithm, "uses")
        return graph

    def _agility_signals(self, asset: str,
                         hardcoded_results: list[dict[str, Any]],
                         extra: list[str]) -> list[str]:
        signals = list(extra)
        for result in hardcoded_results:
            if result.get("asset_id") != asset and len(hardcoded_results) > 1:
                continue
            for kind in result.get("hardcoded", {}):
                signals.append(f"hardcoded_{kind.replace('hardcoded_', '')}"
                               if kind.startswith("hardcoded_") else kind)
        return signals

    def _run_misconfig(self, check: dict[str, Any]) -> list[dict[str, Any]]:
        kind = check.get("kind")
        if kind == "tls":
            return self.misconfig.check_tls(
                tls_version=check.get("tls_version", ""),
                cipher_suite=check.get("cipher_suite", ""),
                pfs=check.get("pfs"), curve=check.get("curve", ""))
        if kind == "certificate":
            return self.misconfig.check_certificate(
                signature_hash=check.get("signature_hash", ""),
                expired=bool(check.get("expired")),
                key_algorithm=check.get("key_algorithm", ""),
                key_size=check.get("key_size"))
        if kind == "dh":
            return self.misconfig.check_dh(dh_group=check.get("dh_group", ""))
        if kind == "ssh":
            return self.misconfig.check_ssh(ciphers=check.get("ciphers"),
                                            kex=check.get("kex"),
                                            macs=check.get("macs"))
        if kind == "vpn":
            return self.misconfig.check_vpn(
                ike_version=check.get("ike_version", ""),
                encryption=check.get("encryption", ""),
                pfs=bool(check.get("pfs")))
        if kind == "mode":
            return self.misconfig.check_mode(mode=check.get("mode", ""),
                                             policy=check.get("policy", "NIST"))
        return []

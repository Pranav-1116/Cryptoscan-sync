from __future__ import annotations

from pathlib import Path

from scanner.detectors.cipher_detector import CipherDetector
from scanner.detectors.hardcoded_key_detector import HardcodedKeyDetector
from scanner.detectors.hmac_detector import HmacDetector
from scanner.detectors.key_generator_detector import KeyGeneratorDetector
from scanner.detectors.message_digest_detector import MessageDigestDetector
from scanner.detectors.signature_detector import SignatureDetector
from scanner.models.raw_finding import RawFinding


class DetectorRegistry:
    def __init__(self, repo_root: Path | None = None):
        self.detectors = [
            CipherDetector(repo_root),
            MessageDigestDetector(repo_root),
            KeyGeneratorDetector(repo_root),
            SignatureDetector(repo_root),
            HmacDetector(repo_root),
            HardcodedKeyDetector(repo_root),
        ]

    def detect_all(self, file_path: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []
        seen: set[tuple] = set()
        for detector in self.detectors:
            for finding in detector.detect(file_path):
                key = (finding.source.file_path, finding.source.line_number, finding.crypto.api_type)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        return findings

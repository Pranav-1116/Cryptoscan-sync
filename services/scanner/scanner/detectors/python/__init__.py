from scanner.detectors.python.hashlib_detector import detect as detect_hashlib
from scanner.detectors.python.cryptography_detector import detect as detect_cryptography

__all__ = ["detect_hashlib", "detect_cryptography"]

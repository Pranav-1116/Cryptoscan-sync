from scanner.detectors.csharp.aes_detector import detect as detect_aes
from scanner.detectors.csharp.bouncycastle_detector import detect as detect_bouncycastle
from scanner.detectors.csharp.hardcoded_key_detector import detect as detect_hardcoded_key
from scanner.detectors.csharp.nsec_detector import detect as detect_nsec
from scanner.detectors.csharp.system_crypto_detector import detect as detect_system_crypto

__all__ = [
    "detect_aes",
    "detect_bouncycastle",
    "detect_hardcoded_key",
    "detect_nsec",
    "detect_system_crypto",
]

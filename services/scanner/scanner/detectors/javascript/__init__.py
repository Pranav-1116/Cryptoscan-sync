from scanner.detectors.javascript.bcrypt_detector import detect as detect_bcrypt
from scanner.detectors.javascript.crypto_js_detector import detect as detect_cryptojs
from scanner.detectors.javascript.hardcoded_secret_detector import detect as detect_hardcoded_secret
from scanner.detectors.javascript.jwt_detector import detect as detect_jwt
from scanner.detectors.javascript.node_crypto_detector import detect as detect_node_crypto
from scanner.detectors.javascript.node_forge_detector import detect as detect_node_forge
from scanner.detectors.javascript.webcrypto_detector import detect as detect_webcrypto

__all__ = [
    "detect_bcrypt",
    "detect_cryptojs",
    "detect_hardcoded_secret",
    "detect_jwt",
    "detect_node_crypto",
    "detect_node_forge",
    "detect_webcrypto",
]

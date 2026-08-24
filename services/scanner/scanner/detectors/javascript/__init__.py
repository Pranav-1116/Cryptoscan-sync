from scanner.detectors.javascript.node_crypto_detector import detect as detect_node_crypto
from scanner.detectors.javascript.crypto_js_detector import detect as detect_cryptojs

__all__ = ["detect_node_crypto", "detect_cryptojs"]

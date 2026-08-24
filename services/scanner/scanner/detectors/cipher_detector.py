from scanner.detectors.base_detector import BaseDetector
from scanner.models.enums import ApiType


class CipherDetector(BaseDetector):
    api_type = ApiType.CIPHER_INSTANCE.value

    def name(self) -> str:
        return "cipher"

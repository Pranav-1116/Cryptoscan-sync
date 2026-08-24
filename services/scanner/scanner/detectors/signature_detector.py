from scanner.detectors.base_detector import BaseDetector
from scanner.models.enums import ApiType


class SignatureDetector(BaseDetector):
    api_type = ApiType.SIGNATURE.value

    def name(self) -> str:
        return "signature"

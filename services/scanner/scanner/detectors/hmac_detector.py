from scanner.detectors.base_detector import BaseDetector
from scanner.models.enums import ApiType


class HmacDetector(BaseDetector):
    api_type = ApiType.MAC.value

    def name(self) -> str:
        return "hmac"

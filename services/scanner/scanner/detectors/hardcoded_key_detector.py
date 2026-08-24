from scanner.detectors.base_detector import BaseDetector
from scanner.models.enums import ApiType


class HardcodedKeyDetector(BaseDetector):
    api_type = ApiType.HARDCODED_KEY.value

    def name(self) -> str:
        return "hardcoded_key"

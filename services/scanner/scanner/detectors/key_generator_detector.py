from scanner.detectors.base_detector import BaseDetector
from scanner.models.enums import ApiType


class KeyGeneratorDetector(BaseDetector):
    api_type = ApiType.KEY_GENERATOR.value

    def name(self) -> str:
        return "key_generator"

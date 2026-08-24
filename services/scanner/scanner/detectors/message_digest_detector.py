from scanner.detectors.base_detector import BaseDetector
from scanner.models.enums import ApiType


class MessageDigestDetector(BaseDetector):
    api_type = ApiType.MESSAGE_DIGEST.value

    def name(self) -> str:
        return "message_digest"

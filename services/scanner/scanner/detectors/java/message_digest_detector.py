"""Java MessageDigest.getInstance detector."""

from scanner.detectors.java._filter import detect_api
from scanner.models.enums import ApiType


class MessageDigestDetector:
    api_type = ApiType.MESSAGE_DIGEST.value

    def name(self) -> str:
        return "java-message-digest"

    def detect(self, file_path, repo_root=None):
        return detect_api(file_path, self.api_type, repo_root=repo_root)


def detect(file_path, repo_root=None):
    return MessageDigestDetector().detect(file_path, repo_root=repo_root)

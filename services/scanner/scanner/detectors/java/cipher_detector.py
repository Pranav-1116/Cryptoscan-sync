"""Java Cipher.getInstance detector."""

from scanner.detectors.java._filter import detect_api
from scanner.models.enums import ApiType


class CipherDetector:
    api_type = ApiType.CIPHER_INSTANCE.value

    def name(self) -> str:
        return "java-cipher"

    def detect(self, file_path, repo_root=None):
        return detect_api(file_path, self.api_type, repo_root=repo_root)


def detect(file_path, repo_root=None):
    return CipherDetector().detect(file_path, repo_root=repo_root)

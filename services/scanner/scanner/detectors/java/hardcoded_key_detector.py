"""Java SecretKeySpec hardcoded-key detector."""

from scanner.detectors.java._filter import detect_api
from scanner.models.enums import ApiType


class HardcodedKeyDetector:
    api_type = ApiType.HARDCODED_KEY.value

    def name(self) -> str:
        return "java-hardcoded-key"

    def detect(self, file_path, repo_root=None):
        return detect_api(file_path, self.api_type, repo_root=repo_root)


def detect(file_path, repo_root=None):
    return HardcodedKeyDetector().detect(file_path, repo_root=repo_root)

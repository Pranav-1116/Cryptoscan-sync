"""Java KeyGenerator.getInstance detector."""

from scanner.detectors.java._filter import detect_api
from scanner.models.enums import ApiType


class KeyGeneratorDetector:
    api_type = ApiType.KEY_GENERATOR.value

    def name(self) -> str:
        return "java-key-generator"

    def detect(self, file_path, repo_root=None):
        return detect_api(file_path, self.api_type, repo_root=repo_root)


def detect(file_path, repo_root=None):
    return KeyGeneratorDetector().detect(file_path, repo_root=repo_root)

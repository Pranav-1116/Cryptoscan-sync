"""First universal runtime adapter: explicit offline Linux manifest only."""

import sys
from inventory.host import collect
from shared_models.collection import TargetSpec


class OfflineLinuxCollector:
    def validate_scope(self, target: TargetSpec) -> None:
        if (
            target.collection_method != "offline_host"
            or not target.manifest
            or target.manifest.platform != "linux"
            or not sys.platform.startswith("linux")
            or any(i.kind == "OCI_IMAGE_METADATA" for i in target.manifest.inputs)
        ):
            raise ValueError("Collector/platform is not supported by offline-linux/v1")
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        if not target.not_before <= now < target.manifest.expires_at:
            raise ValueError("Outside explicitly approved collection time window")

    def collect(self, target: TargetSpec):
        self.validate_scope(target)
        return collect(target.manifest)  # existing no-follow, bounded, least-privilege implementation

    def health(self):
        return {
            "collector": "offline-linux/v1",
            "platform_supported": sys.platform.startswith("linux"),
            "production_execution_qualified": False,
            "remote_execution": False,
        }


class OfflineWindowsCollector:
    """Candidate only: local native user, no registry-job production admission."""

    def validate_scope(self, target: TargetSpec) -> None:
        from datetime import datetime, timezone

        if (
            target.collection_method != "offline_host"
            or not target.manifest
            or target.manifest.platform != "windows"
            or sys.platform != "win32"
        ):
            raise ValueError("Collector/platform is not supported by offline-windows/candidate-v1")
        if not target.not_before <= datetime.now(timezone.utc) < target.manifest.expires_at:
            raise ValueError("Outside explicitly approved collection time window")

    def collect(self, target: TargetSpec):
        self.validate_scope(target)
        return collect(target.manifest)

    def health(self):
        return {
            "collector": "offline-windows/candidate-v1",
            "platform_supported": sys.platform == "win32",
            "windows_execution_qualified": False,
            "production_execution_qualified": False,
            "remote_execution": False,
        }


class OfflineOciMetadataCollector:
    """Candidate inspection only; no image pulls, layer IO, extraction or runtime."""

    def validate_scope(self, target: TargetSpec) -> None:
        from datetime import datetime, timezone

        if (
            target.collection_method != "container"
            or not target.manifest
            or target.manifest.platform != "linux"
            or not sys.platform.startswith("linux")
            or target.credential_ref is not None
            or target.environment != target.manifest.environment
            or any(i.kind != "OCI_IMAGE_METADATA" or i.input_id in target.exclusions for i in target.manifest.inputs)
            or not target.not_before <= datetime.now(timezone.utc) < target.manifest.expires_at
        ):
            raise ValueError("Exact offline OCI metadata candidate scope/window required")

    def collect(self, target: TargetSpec):
        self.validate_scope(target)
        return collect(target.manifest)

    def health(self):
        return {
            "collector": "offline-oci-metadata/candidate-v1",
            "production_execution_qualified": False,
            "server_execution": False,
            "layer_contents_verified": False,
            "runtime_observed": False,
            "platform_supported": sys.platform.startswith("linux"),
        }

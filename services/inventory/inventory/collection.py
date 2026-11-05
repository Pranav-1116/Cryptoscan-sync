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
            or any(
                i.kind
                in {
                    "OCI_IMAGE_METADATA",
                    "OCI_IMAGE_CONTENT",
                    "OCI_RUNTIME_PROCESS",
                    "NETWORK_TLS_SESSION",
                    "NETWORK_TLS13_KEY_SHARE",
                    "NETWORK_TLS13_HYBRID",
                }
                for i in target.manifest.inputs
            )
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


class OfflineContainerCollector(OfflineOciMetadataCollector):
    """Explicit content/runtime candidate, not an admitted production executor."""

    def validate_scope(self, target: TargetSpec) -> None:
        from datetime import datetime, timezone
        from shared_models.oci_content import KINDS

        if (
            target.collection_method != "container"
            or not target.manifest
            or target.manifest.platform != "linux"
            or not sys.platform.startswith("linux")
            or target.credential_ref is not None
            or target.environment != target.manifest.environment
            or any(i.kind not in KINDS or i.input_id in target.exclusions for i in target.manifest.inputs)
            or not target.not_before <= datetime.now(timezone.utc) < target.manifest.expires_at
        ):
            raise ValueError("Explicit scoped container content/runtime candidate required")

    def health(self):
        return {
            "collector": "offline-container-content/candidate-v1",
            "production_execution_qualified": False,
            "server_execution": False,
            "platform_supported": sys.platform.startswith("linux"),
        }


class ApprovedTlsClientOfferCollector:
    """Explicit operator-run candidate only; observes the ClientHellos that arrive.

    Where the session probe dials out and records what a server selected, this binds one
    approved numeric endpoint and records what connecting clients offer. It is the
    collector behind the protocol floor's runtime client-acceptance axis, and it completes
    no handshakes: an offer is never a negotiation.
    """

    def validate_scope(self, target: TargetSpec) -> None:
        from datetime import datetime, timezone
        from shared_models.tls_client_offer import KIND, OPERATION, client_offer_resource, endpoint

        if (
            target.collection_method != "network"
            or target.allowed_operations != [OPERATION]
            or not target.manifest
            or target.manifest.platform != "linux"
            or not sys.platform.startswith("linux")
            or target.credential_ref is not None
            or target.environment != target.manifest.environment
            or len(target.manifest.inputs) != 1
            or target.manifest.inputs[0].kind != KIND
            or target.manifest.inputs[0].input_id in target.exclusions
            or not target.not_before <= datetime.now(timezone.utc) < target.manifest.expires_at
        ):
            raise ValueError("Exact single-endpoint client-offer observation approval required")
        address, port = client_offer_resource(target.manifest.inputs[0].path)
        if target.address != endpoint(address, port):
            raise ValueError("Target address must bind the approved numeric observation endpoint")

    def collect(self, target: TargetSpec):
        from inventory.tls_client_offer import probe_client_offers

        self.validate_scope(target)
        from shared_models.host_collection import digest

        reviewed = digest(target)

        def approved_probe(item, limit, charge, expires):
            return probe_client_offers(item, limit, charge, expires, reviewed_target_sha256=reviewed)

        return collect(target.manifest, network_session=approved_probe)

    def health(self):
        return {
            "collector": "approved-tls-client-offer/candidate-v1",
            "server_execution": False,
            "production_execution_qualified": False,
            "active_probe": True,
            "inbound_observation": True,
            "handshake_completed": False,
            "platform_supported": sys.platform.startswith("linux"),
        }


class ApprovedTlsSessionCollector:
    """Explicit operator-run candidate only; no HTTP dispatch or production admission."""

    def __init__(self, *, include_key_share=False, include_hybrid=False):
        self.include_key_share = include_key_share
        self.include_hybrid = include_hybrid

    def validate_scope(self, target: TargetSpec) -> None:
        from datetime import datetime, timezone
        from shared_models.tls_session import KIND, OPERATION, endpoint, tls_resource
        from shared_models.tls_key_share import KIND as KEY_KIND, key_share_resource
        from shared_models.tls_hybrid import KIND as HYBRID_KIND, hybrid_resource

        if (
            target.collection_method != "network"
            or target.allowed_operations != [OPERATION]
            or not target.manifest
            or target.manifest.platform != "linux"
            or not sys.platform.startswith("linux")
            or target.credential_ref is not None
            or target.environment != target.manifest.environment
            or len(target.manifest.inputs) != 1
            or target.manifest.inputs[0].kind
            not in (
                {KIND}
                | ({KEY_KIND} if self.include_key_share else set())
                | ({HYBRID_KIND} if self.include_hybrid else set())
            )
            or target.manifest.inputs[0].input_id in target.exclusions
            or not target.not_before <= datetime.now(timezone.utc) < target.manifest.expires_at
        ):
            raise ValueError("Exact single-session active TLS approval required")
        item = target.manifest.inputs[0]
        resource = (
            hybrid_resource
            if item.kind == HYBRID_KIND
            else key_share_resource
            if item.kind == KEY_KIND
            else tls_resource
        )
        address, port, *_ = resource(item.path)
        if target.address != endpoint(address, port):
            raise ValueError("Target address must bind the approved numeric socket endpoint")

    def collect(self, target: TargetSpec):
        from inventory.tls_session import probe_session

        self.validate_scope(target)
        from shared_models.host_collection import digest

        reviewed = digest(target)

        def approved_probe(item, limit, charge, expires):
            return probe_session(item, limit, charge, expires, reviewed_target_sha256=reviewed)

        return collect(target.manifest, network_session=approved_probe)

    def health(self):
        return {
            "collector": "approved-tls-session/candidate-v1",
            "server_execution": False,
            "production_execution_qualified": False,
            "active_probe": True,
            "platform_supported": sys.platform.startswith("linux"),
        }

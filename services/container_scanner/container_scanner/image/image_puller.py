"""Spec-named image puller (docker / skopeo / podman)."""

from container_scanner.image.puller import ImagePullError, resolve_image

__all__ = ["ImagePullError", "resolve_image"]

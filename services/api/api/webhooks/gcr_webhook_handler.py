"""Spec-named re-export of the GCR webhook adapter."""

from api.github.gcr_webhook_handler import handle_gcr_event

__all__ = ["handle_gcr_event"]

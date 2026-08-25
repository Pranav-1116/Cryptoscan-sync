"""Spec-named re-export of the ACR webhook adapter."""

from api.github.acr_webhook_handler import handle_acr_event

__all__ = ["handle_acr_event"]

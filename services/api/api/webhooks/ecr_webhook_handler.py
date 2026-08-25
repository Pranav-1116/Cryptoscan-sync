"""Spec-named re-export of the ECR webhook adapter."""

from api.github.ecr_webhook_handler import handle_ecr_event

__all__ = ["handle_ecr_event"]

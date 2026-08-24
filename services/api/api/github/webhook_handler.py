"""
GitHub webhook handler.
Orchestrates validation and routing of webhook events.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class GitHubWebhookHandler:
    """
    High-level handler for GitHub webhook events.

    Responsibilities:
    - Event type routing
    - Logging with structured context
    - Extensibility for future event types (PR, status, etc.)
    """

    SUPPORTED_EVENTS = frozenset({"push"})

    def is_supported_event(self, event_type: str) -> bool:
        """Return True if we handle this GitHub event type."""
        return event_type in self.SUPPORTED_EVENTS

    def log_event_received(
        self,
        event_type: str,
        delivery_id: str | None,
        payload: Dict[str, Any],
    ) -> None:
        """Emit structured log for received webhook event."""
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        logger.info(
            "github_webhook_event_received",
            extra={
                "event_type": event_type,
                "delivery_id": delivery_id,
                "repo": repo_name,
            },
        )
"""Shared vocabulary for the live estate planes.

A live plane can fail in two very different ways, and the estate job must report
them differently:

* :class:`PlaneNotConfigured` — we were never given a way to ask (no kubeconfig,
  no cloud credentials). The plane is ``NOT_ATTEMPTED``: nothing was asked, so
  nothing is claimed, and the affected BOMs are named as incomplete.
* any other exception — we asked and the source failed. The plane is ``FAILED``
  with an impact statement, never an empty result.

Keeping the marker in one module means a new collector cannot accidentally invent
its own "not configured" signal that the job does not understand.
"""

from __future__ import annotations


class PlaneNotConfigured(RuntimeError):
    """No credentials/endpoint for this source: NOT_ATTEMPTED, not a failure."""

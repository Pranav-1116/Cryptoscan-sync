"""HTTP conditional GET for JSON responses — the request-optimization layer.

Dashboards poll: the twin page, the scan list and the BOM catalog are re-read on
a timer, and almost every one of those reads is unchanged from the last.  This
middleware gives every eligible JSON GET a strong ``ETag`` computed over exactly
the bytes served and answers a matching ``If-None-Match`` with ``304`` and an
empty body — the client keeps its cached copy and the wire carries headers only.

Design boundaries (deliberate):

* GET/HEAD only.  Mutating requests are never conditional.
* ``application/json`` bodies only, and only up to ``max_body`` bytes.  Bigger
  bodies stream through untouched — a hash is not worth buffering a large
  export for, and the export routes already manage their own caching.
* Streams (``text/event-stream``) and binary downloads pass through unbuffered:
  the first response chunk decides, and nothing is held back for hashing.
* The ETag covers the representation actually served (post-gzip, when the
  client asked for gzip), so the validator is per-representation correct and
  ``Vary: Accept-Encoding`` is always set alongside it.
* ``Cache-Control: private, no-cache`` — the response may be stored by the
  browser but must be revalidated.  This is an authenticated, tenant-scoped
  API: shared caches must never keep these bodies, and stale data must never
  be served without asking.
* A route that already set its own ``ETag`` or ``Cache-Control: no-store`` is
  left exactly as it wrote it.
"""

from __future__ import annotations

import hashlib


class ConditionalGetMiddleware:
    """Pure-ASGI middleware: ETag over JSON GET responses, 304 on a match."""

    def __init__(self, app, max_body: int = 2 * 1024 * 1024):
        self.app = app
        self.max_body = max_body

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method", "").upper() not in ("GET", "HEAD"):
            await self.app(scope, receive, send)
            return

        request_headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        if_none_match = request_headers.get("if-none-match", "").strip()
        accept = request_headers.get("accept", "")
        # Streaming and negotiation cases keep their own transport semantics.
        if "text/event-stream" in accept:
            await self.app(scope, receive, send)
            return

        state = {"status": 0, "headers": None, "chunks": [], "size": 0, "abandoned": False}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                state["headers"] = list(message.get("headers", []))
                return
            if message["type"] == "http.response.body":
                if state["abandoned"]:
                    await send(message)
                    return
                state["chunks"].append(message.get("body", b""))
                state["size"] += len(message.get("body", b""))
                if not message.get("more_body", False):
                    await self._finish(send, state, if_none_match)
                elif state["size"] > self.max_body:
                    # Too big to hash: flush what is buffered and stream the rest.
                    state["abandoned"] = True
                    await self._flush_raw(send, state)
                    await send(message)
                return
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ------------------------------------------------------------------ internals

    def _header(self, headers, name: str) -> str | None:
        target = name.lower().encode()
        for key, value in headers:
            if key.lower() == target:
                return value.decode("latin-1")
        return None

    async def _flush_raw(self, send, state):
        start = {"type": "http.response.start", "status": state["status"], "headers": state["headers"] or []}
        await send(start)
        for index, chunk in enumerate(state["chunks"]):
            await send({
                "type": "http.response.body",
                "body": chunk,
                "more_body": index < len(state["chunks"]) - 1,
            })
        state["chunks"] = []

    async def _finish(self, send, state, if_none_match: str):
        headers = state["headers"] or []
        body = b"".join(state["chunks"])
        state["chunks"] = []
        content_type = (self._header(headers, "content-type") or "").lower()
        already_tagged = self._header(headers, "etag") is not None
        no_store = "no-store" in (self._header(headers, "cache-control") or "").lower()

        eligible = (
            state["status"] == 200
            and "application/json" in content_type
            and not already_tagged
            and not no_store
            and len(body) <= self.max_body
        )
        if not eligible:
            await send({"type": "http.response.start", "status": state["status"], "headers": headers})
            await send({"type": "http.response.body", "body": body})
            return

        etag = '"' + hashlib.sha256(body).hexdigest() + '"'
        out = [(k, v) for k, v in headers if k.lower() not in (b"etag", b"vary")]
        out.append((b"etag", etag.encode()))
        # Per-representation correctness: gzip and identity are different bytes
        # with different tags, so caches must key on the encoding.
        out.append((b"vary", b"Accept-Encoding"))
        if self._header(headers, "cache-control") is None:
            out.append((b"cache-control", b"private, no-cache"))

        if if_none_match and if_none_match != "*" and etag in [t.strip() for t in if_none_match.split(",")]:
            await send({"type": "http.response.start", "status": 304, "headers": out})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return

        await send({"type": "http.response.start", "status": 200, "headers": out})
        await send({"type": "http.response.body", "body": body, "more_body": False})

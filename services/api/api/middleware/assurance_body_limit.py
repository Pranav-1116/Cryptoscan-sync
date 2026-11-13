"""Hard streaming body cap BEFORE FastAPI JSON/base64 parsing on new workflows."""
from starlette.responses import JSONResponse


class AssuranceBodyLimit:
    def __init__(self, app, prefix="/api/v1/assurance/", label="Assurance",
                 max_bytes=2 * 1048576):
        self.app, self.prefix, self.label = app, prefix, label
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith(self.prefix):
            await self.app(scope, receive, send)
            return
        # Bound the wire before parsing, including chunked/missing Content-Length.
        # Raw assurance uploads retain a tighter 1 MiB handler cap.
        data, count = bytearray(), 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            count += len(message.get("body", b""))
            if count > self.max_bytes:
                size = (f"{self.max_bytes // 1048576} MiB"
                        if self.max_bytes % 1048576 == 0 else f"{self.max_bytes} bytes")
                await JSONResponse({"detail": f"{self.label} request exceeds {size} wire limit"}, status_code=413, headers={"Cache-Control": "no-store"})(scope, receive, send)
                return
            data.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        messages = [{"type": "http.request", "body": bytes(data), "more_body": False}]
        headers = dict(scope.get("headers", []))
        media_type = headers.get(b"content-type", b"").split(b";")[0].strip().lower()
        if count and (not media_type or media_type == b"application/json" or media_type.startswith(b"application/") and media_type.endswith(b"+json")):
            from shared_models.qualified_export import bounded_json
            try:
                bounded_json(b"".join(m.get("body", b"") for m in messages), max_bytes=self.max_bytes)
            except (ValueError, TypeError, UnicodeError, RecursionError):
                await JSONResponse({"detail": f"Malformed, duplicate-key or over-nested {self.label.lower()} JSON"}, status_code=422, headers={"Cache-Control": "no-store"})(scope, receive, send)
                return
        async def bounded_receive():
            if messages:
                return messages.pop(0)
            return await receive()
        async def private_send(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control"]
                message = {**message, "headers": headers + [(b"cache-control", b"no-store")]}
            await send(message)
        await self.app(scope, bounded_receive, private_send)

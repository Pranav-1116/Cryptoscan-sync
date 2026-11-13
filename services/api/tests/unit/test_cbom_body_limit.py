"""Wire limits must run before policy/JSON parsers, even without Content-Length."""
import pytest
from api.middleware.assurance_body_limit import AssuranceBodyLimit


@pytest.mark.asyncio
@pytest.mark.parametrize("payload,status", [(b'{"key":1,"key":2}',422),
    (b'['*25+b'0'+b']'*25,422), (b'{"key":NaN}',422),
    (b'x'*(2*1048576+1),413), (b'{}',204)])
async def test_cbom_chunked_wire_limits_without_content_length(payload, status):
    reached = []
    messages = []
    chunks = [payload[i:i+8192] for i in range(0,len(payload),8192)]
    incoming = iter([{"type":"http.request", "body":chunk, "more_body":i<len(chunks)-1}
                     for i,chunk in enumerate(chunks)])
    async def receive():
        return next(incoming)
    async def send(message):
        messages.append(message)
    async def app(scope, receive, send):
        reached.append(True)
        body = await receive()
        assert body["body"] == payload
        await send({"type":"http.response.start","status":204,"headers":[]})
        await send({"type":"http.response.body","body":b""})
    middleware = AssuranceBodyLimit(app,prefix="/api/v1/cbom/",label="CBOM")
    await middleware({"type":"http","path":"/api/v1/cbom/ingest","headers":[(b"content-type",b"application/json")]},receive,send)
    assert messages[0]["status"] == status
    assert bool(reached) == (status == 204)
    assert (b"cache-control",b"no-store") in messages[0]["headers"]


@pytest.mark.asyncio
async def test_binary_chunked_upload_is_refused_before_json_parser():
    reached = []
    messages = []
    incoming = iter([
        {"type": "http.request", "body": b"a" * 80, "more_body": True},
        {"type": "http.request", "body": b"b" * 49, "more_body": False},
    ])

    async def receive():
        return next(incoming)

    async def send(message):
        messages.append(message)

    async def app(scope, receive, send):
        reached.append(True)

    middleware = AssuranceBodyLimit(
        app, prefix="/api/v1/binary/", label="Binary", max_bytes=128)
    await middleware({"type": "http", "path": "/api/v1/binary/scan",
                      "headers": [(b"content-type", b"application/json")]}, receive, send)
    assert messages[0]["status"] == 413
    assert not reached


def test_binary_wire_limit_is_registered_on_real_api():
    from api.main import create_app

    limits = [middleware.kwargs for middleware in create_app().user_middleware
              if middleware.cls is AssuranceBodyLimit]
    assert any(item.get("prefix") == "/api/v1/binary/" and
               item.get("max_bytes") == 9 * 1048576 for item in limits)
    assert any(item.get("prefix") == "/api/v1/performance/captures/" and
               item.get("max_bytes") == 1048576 for item in limits)


def test_binary_inline_upload_is_bounded_before_decode():
    from pydantic import ValidationError
    from api.routers.binary_intelligence import (
        MAX_INLINE_BASE64_CHARS, RescanRequest, ScanRequest)

    for request in (ScanRequest, RescanRequest):
        with pytest.raises(ValidationError):
            request.model_validate({"tenant_id": "test", "artifact_base64":
                                    "A" * (MAX_INLINE_BASE64_CHARS + 1)})

"""Runtime transport adapters for outbound connectors (features 18/19/17).

The connector/sync logic is transport-injected for determinism. At RUNTIME the
platform needs real bindings; these factories provide them with LAZY third-party
imports so the module imports (and tests run) without the SDKs installed:

- urllib HTTP GET/POST (Splunk HEC, Elastic _bulk, Slack/Teams webhooks,
  ServiceNow/Jira REST) — stdlib only, always available.
- Kafka producer via ``confluent_kafka`` (optional dependency).
- RabbitMQ publisher via ``pika`` (optional dependency).

Each adapter honours the injected SSRF-safe URL validation at the caller layer;
here we only perform the I/O and normalise results/errors.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Callable

from .connectors import HttpResult


# ----------------------------------------------------------------- HTTP ---- #
def urllib_post(timeout: float = 10.0) -> Callable[..., HttpResult]:
    """Real urllib POST callable matching the connector ``post(url, content=,
    headers=)`` contract. Returns HttpResult; never raises for HTTP errors."""

    def _post(url: str, *, content: bytes, headers: dict, timeout: float = timeout,
              method: str = "POST") -> HttpResult:
        req = urllib.request.Request(url, data=content, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                body = resp.read().decode("utf-8", "replace")
                return HttpResult(ok=200 <= resp.status < 300, status=resp.status, body=body)
        except urllib.error.HTTPError as exc:
            return HttpResult(ok=False, status=exc.code,
                              body=exc.read().decode("utf-8", "replace"), error=f"HTTP {exc.code}")
        except urllib.error.URLError as exc:
            return HttpResult(ok=False, status=None, error=f"network: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            return HttpResult(ok=False, error=str(exc))
    return _post


def urllib_get(timeout: float = 10.0) -> Callable[..., HttpResult]:
    """Real urllib GET for bidirectional ticket sync (ServiceNow/Jira polls)."""

    def _get(url: str, *, headers: dict | None = None, timeout: float = timeout) -> HttpResult:
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return HttpResult(ok=200 <= resp.status < 300, status=resp.status,
                                  body=resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            return HttpResult(ok=False, status=exc.code,
                              body=exc.read().decode("utf-8", "replace"), error=f"HTTP {exc.code}")
        except urllib.error.URLError as exc:
            return HttpResult(ok=False, status=None, error=f"network: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            return HttpResult(ok=False, error=str(exc))
    return _get


# ---------------------------------------------------------------- Kafka ---- #
def kafka_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("confluent_kafka") is not None


def confluent_kafka_producer(bootstrap: str, *, extra_conf: dict | None = None):
    """Build a Kafka ``produce(topic, value: bytes, headers: dict)`` callable.

    Lazily imports confluent_kafka; raises RuntimeError with an actionable
    message if the SDK isn't installed. The returned callable flushes per
    message so delivery is durable and errors surface deterministically."""
    try:
        from confluent_kafka import Producer  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "confluent_kafka is not installed; install confluent-kafka or inject "
            "a test producer") from exc

    conf = {"bootstrap.servers": bootstrap,
            "enable.idempotence": True, "acks": "all",
            "message.send.max.retries": 5, **(extra_conf or {})}
    producer = Producer(conf)

    def produce(topic: str, value: bytes, headers: dict) -> Any:
        hdrs = [(k, str(v).encode()) for k, v in (headers or {}).items()]
        producer.produce(topic, value=value, headers=hdrs)
        producer.poll(0)
        producer.flush(timeout=10)
        return {"topic": topic, "bytes": len(value), "delivered": True}
    return produce


# ------------------------------------------------------------- RabbitMQ ---- #
def rabbit_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("pika") is not None


def pika_publisher(amqp_url: str, *, exchange_declare: bool = True):
    """Build a RabbitMQ ``publish(exchange, routing_key, body: bytes, props)``
    callable over pika. Lazily imports pika; raises if absent."""
    try:
        import pika  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("pika is not installed; install pika or inject a test publisher") from exc

    params = pika.URLParameters(amqp_url)
    conn = pika.BlockingConnection(params)
    channel = conn.channel()
    if exchange_declare:
        # durable topic exchange for findings; passive declare safe for pre-existing
        channel.exchange_declare(exchange="security", exchange_type="topic", durable=True)

    def publish(exchange: str, routing_key: str, body: bytes, properties: dict) -> Any:
        props = pika.BasicProperties(
            delivery_mode=2,  # persistent
            headers=properties or {},
            content_type="application/json")
        channel.basic_publish(exchange=exchange, routing_key=routing_key, body=body,
                              properties=props, mandatory=True)
        return {"exchange": exchange, "routing_key": routing_key, "bytes": len(body)}
    return publish


# ------------------------------------------------------- ticket transports -- #
def servicenow_get_transport(instance: str, basic_auth: str):
    """Return a ``get(url, headers=)`` callable pre-authenticated for ServiceNow.
    URL is constructed by TicketSync; we add basic auth headers."""
    get = urllib_get()

    def _get(url: str, *, headers: dict | None = None):
        h = {"Accept": "application/json", "Authorization": f"Basic {basic_auth}", **(headers or {})}
        return get(url, headers=h)
    return _get


def jira_get_transport(basic_auth: str):
    """Return a ``get(url, headers=)`` callable pre-authenticated for Jira."""
    get = urllib_get()

    def _get(url: str, *, headers: dict | None = None):
        h = {"Accept": "application/json", "Authorization": f"Basic {basic_auth}", **(headers or {})}
        return get(url, headers=h)
    return _get


def adapter_status() -> dict[str, bool]:
    """Report which optional runtime transports are available (for the UI/health)."""
    return {"http": True, "kafka": kafka_available(), "rabbitmq": rabbit_available()}

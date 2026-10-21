"""Verified TLS and optional Sentinel routing for the realtime Redis boundary.

Configuration checks are not HA, persistence or security certification. Cluster
is intentionally unsupported by the journal's cross-key transaction design.
"""

import json
from urllib.parse import urlsplit, parse_qs, unquote


class RedisConfigurationError(ValueError):
    pass


def validate_realtime_redis(settings):
    url = urlsplit(settings.REDIS_URL)
    query = parse_qs(url.query, keep_blank_values=True)
    if url.scheme not in {"redis", "rediss", "unix"}:
        raise RedisConfigurationError("Realtime Redis requires redis/rediss/unix, not Cluster")
    if settings.is_production:
        if url.scheme != "rediss" or not url.hostname or not url.username or not url.password:
            raise RedisConfigurationError(
                "Production realtime Redis requires rediss with a named ACL user and password"
            )
        if query.get("ssl_cert_reqs", ["required"])[-1].lower() != "required":
            raise RedisConfigurationError("Realtime Redis certificate verification cannot be disabled")
        if query.get("ssl_check_hostname", ["true"])[-1].lower() not in {"true", "1"}:
            raise RedisConfigurationError("Realtime Redis hostname verification cannot be disabled")
        if unquote(url.username) == "default":
            raise RedisConfigurationError("Production realtime Redis requires a dedicated non-default ACL user")
    nodes = []
    if settings.REDIS_SENTINELS:
        try:
            raw = json.loads(settings.REDIS_SENTINELS)
            if not isinstance(raw, list) or not 1 <= len(raw) <= 9:
                raise ValueError()
            for host, port in raw:
                if not isinstance(host, str) or not host.strip() or type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError()
                nodes.append((host, port))
        except (TypeError, ValueError) as exc:
            raise RedisConfigurationError("REDIS_SENTINELS must be a JSON list of host/port pairs") from exc
        if not settings.REDIS_SENTINEL_MASTER or url.scheme != "rediss":
            raise RedisConfigurationError("Sentinel requires a master service name and rediss data connections")
        if settings.is_production and (
            len(set(nodes)) < 3 or not settings.REDIS_SENTINEL_USERNAME or not settings.REDIS_SENTINEL_PASSWORD
        ):
            raise RedisConfigurationError(
                "Production Sentinel requires three distinct endpoints and dedicated ACL credentials"
            )
        # Query-string pool overrides must not smuggle a second unverified
        # transport or credentials into the discovered master connections.
        if query:
            raise RedisConfigurationError(
                "Sentinel Redis URL query overrides are unsupported; use explicit TLS settings"
            )
    elif settings.REDIS_SENTINEL_MASTER:
        raise RedisConfigurationError("Sentinel master configured without Sentinel endpoints")
    return url, nodes


def realtime_redis_client(settings, *, decode_responses=False):
    import redis

    url, nodes = validate_realtime_redis(settings)
    options = {"socket_timeout": 2, "socket_connect_timeout": 2, "decode_responses": decode_responses}
    tls = {"ssl_cert_reqs": "required", "ssl_check_hostname": True}
    if settings.REDIS_CA_CERTS:
        tls["ssl_ca_certs"] = settings.REDIS_CA_CERTS
    if not nodes:
        if url.scheme == "rediss":
            options.update(tls)
        client = redis.Redis.from_url(settings.REDIS_URL, **options)
        if settings.is_production:
            client.replay_bind_primary_epoch = True
        return client
    from redis.sentinel import Sentinel

    sentinel = Sentinel(
        nodes,
        sentinel_kwargs={
            **options,
            **tls,
            "ssl": True,
            "username": settings.REDIS_SENTINEL_USERNAME,
            "password": settings.REDIS_SENTINEL_PASSWORD,
        },
        **options,
        **tls,
        ssl=True,
        username=unquote(url.username or ""),
        password=unquote(url.password or ""),
        db=int(url.path.lstrip("/") or 0),
    )
    # SentinelConnectionPool reconnects to the elected primary. Journals still
    # expose unavailable/reset/gap conditions; asynchronous replication is not
    # upgraded to lossless or exactly-once semantics by this routing choice.
    client = sentinel.master_for(settings.REDIS_SENTINEL_MASTER)
    client.replay_bind_primary_epoch = True
    return client


def probe_journal_commands(client):
    """Exercise actual journal commands on bounded disposable scratch keys.

    Required ACL: application command set plus DEL on the qualification prefix,
    and PUBLISH on its scratch channel. No bank journal is mutated.
    """
    import uuid
    from api.events.redis_estate_journal import RedisEstateJournal
    from api.events.estate_replay import replay_page

    root = "zelinx:events:qualification:" + uuid.uuid4().hex
    keys = [root + suffix for suffix in (":meta", ":stream", ":global", ":sequence")]
    journal = RedisEstateJournal(client, retention=2)
    journal.keys = lambda owner: (keys[0], keys[1])
    try:
        event = {"id": client.incr(keys[3]), "tenant_id": None, "type": "qualification", "payload": {}}
        journal.append(event, global_stream=keys[2], channel=root + ":channel", node="probe", global_retention=2)
        page = replay_page(journal.page, None, limit=2)
        if len(page["events"]) != 1 or not page["complete"]:
            raise RuntimeError("Journal command probe incomplete")
    finally:
        client.delete(*keys)

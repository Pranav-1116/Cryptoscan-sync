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
        if query:
            raise RedisConfigurationError("Production Redis URL query overrides are unsupported; use explicit verified TLS settings")
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


def verified_redis_client(settings, *, decode_responses=False, socket_timeout=2):
    import redis

    url, nodes = validate_realtime_redis(settings)
    options = {"socket_timeout": socket_timeout, "socket_connect_timeout": 2, "decode_responses": decode_responses}
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



def connection_settings(settings, role, *, url=None):
    """Explicit per-consumer overrides; never mix a role URL with base Sentinel.

    Credentials remain deployment environment/configuration, never receipts.
    """
    import os
    from types import SimpleNamespace
    prefix = "CRYPTOSCAN_REDIS_" + role.upper() + "_"
    dedicated = prefix + "URL" in os.environ
    values = {"is_production": getattr(settings, "is_production", str(getattr(settings, "ENVIRONMENT", os.getenv("ENVIRONMENT", "production"))).lower() in {"production", "prod"}),
              "REDIS_URL": os.environ.get(prefix + "URL", url if url is not None else settings.REDIS_URL)}
    for suffix in ("CA_CERTS", "SENTINELS", "SENTINEL_MASTER", "SENTINEL_USERNAME", "SENTINEL_PASSWORD"):
        fallback = "" if dedicated and suffix != "CA_CERTS" else getattr(settings, "REDIS_" + suffix, "")
        values["REDIS_" + suffix] = os.environ.get(prefix + suffix, fallback)
    return SimpleNamespace(**values)


def connection_fingerprint(config):
    """Cache identity includes trust/credential/Sentinel rotation, never exposes it."""
    import hashlib
    import os
    fields = {name: getattr(config, name, "") for name in (
        "REDIS_URL", "REDIS_CA_CERTS", "REDIS_SENTINELS", "REDIS_SENTINEL_MASTER",
        "REDIS_SENTINEL_USERNAME", "REDIS_SENTINEL_PASSWORD", "is_production")}
    ca = fields["REDIS_CA_CERTS"]
    if ca:
        try:
            info = os.stat(ca)
            fields["ca_file_revision"] = (info.st_ino, info.st_mtime_ns, info.st_size)
        except OSError:
            fields["ca_file_revision"] = "UNAVAILABLE"
    return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def probe_role_commands(client, role):
    """Bounded scratch command exercise; not a dependency health check or HA proof.

    Qualification ACL must permit cryptoscan:qualification:* keys. All writes
    are isolated from real queues, quotas, login state and customer journals.
    """
    import uuid
    root = "cryptoscan:qualification:" + uuid.uuid4().hex
    def require(condition):
        if not condition:
            raise RuntimeError("Redis consumer command probe failed")
    keys = [root + suffix for suffix in (":value", ":queue", ":processing", ":count", ":stream")]
    try:
        client.ping()
        if role == "queue":
            client.set(keys[0], "lease", ex=60)
            client.rpush(keys[1], "receipt")
            require(client.blmove(keys[1], keys[2], 1, "LEFT", "RIGHT") in {b"receipt", "receipt"})
            require(client.lrange(keys[2], 0, -1) in ([b"receipt"], ["receipt"]))
            require(client.lrem(keys[2], 1, "receipt") == 1)
        elif role == "rate_limit":
            require(client.incr(keys[3]) == 1)
            require(client.expire(keys[3], 60))
            require(client.ttl(keys[3]) > 0)
        elif role == "realtime":
            client.xadd(keys[4], {"event": "receipt"})
            require(len(client.xrange(keys[4], "-", "+")) == 1)
            client.publish(root + ":channel", "qualification")
        elif role == "sso_state":
            require(client.set(keys[0], "request", ex=60, nx=True))
            require(client.getdel(keys[0]) in {b"request", "request"})
            require(client.get(keys[0]) is None)
        elif role in {"platform_state", "current_run", "telecom"}:
            require(client.set(keys[0], "state", ex=60))
            require(client.get(keys[0]) in {b"state", "state"})
        elif role != "health":
            raise ValueError("Unknown Redis consumer role")
        return {"role": role, "commands_exercised": True, "deployment_qualified": False}
    finally:
        if role != "health":
            client.delete(*keys)

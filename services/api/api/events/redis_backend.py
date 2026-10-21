"""Realtime command qualification; all Redis transports share verified routing."""
from shared_models.redis_connection import (  # noqa: F401 — compatibility exports
    RedisConfigurationError, validate_realtime_redis,
    verified_redis_client as realtime_redis_client,
)

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

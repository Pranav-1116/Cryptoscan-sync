"""DESTRUCTIVE, opt-in disposable Redis lab tests, never run on bank services.

Prepare scripts/prepare_replay_redis_lab.py's six-node topology, then explicitly
set ESTATE_REPLAY_REDIS_LAB and ESTATE_REPLAY_ALLOW_DESTRUCTIVE_LAB=1. Tests change
ACLs, request Sentinel failover and shut down a primary. No FLUSH command runs.
"""

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import redis
from api.config.settings import APISettings
from api.events.bus import EventBus
from api.events.estate_replay import ReplayError
from api.events.redis_backend import realtime_redis_client, probe_journal_commands
from api.events.redis_estate_journal import RedisEstateJournal
from api.events.redis_sync import start_redis_federation

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("ESTATE_REPLAY_REDIS_LAB") or os.environ.get("ESTATE_REPLAY_ALLOW_DESTRUCTIVE_LAB") != "1",
        reason="explicit disposable TLS/Sentinel lab and destructive-test approval required",
    ),
]


@dataclass(repr=False)
class Lab:
    config: object = field(repr=False)
    state: dict = field(repr=False)
    client: object = field(repr=False)
    namespace: str

    def operator(self, port):
        return redis.Redis(
            host="127.0.0.1",
            port=port,
            ssl=True,
            ssl_ca_certs=self.config.REDIS_CA_CERTS,
            ssl_cert_reqs="required",
            ssl_check_hostname=True,
            username="operator",
            password=self.state["passwords"]["operator"],
            socket_timeout=3,
            socket_connect_timeout=2,
        )

    def master(self):
        with self.operator(self.state["sentinel_ports"][0]) as sentinel:
            return int(sentinel.sentinel_get_master_addr_by_name("estate-lab")[1])


@pytest.fixture()
def lab(monkeypatch):
    state = json.loads(Path(os.environ["ESTATE_REPLAY_REDIS_LAB"]).read_text())
    assert state["disposable"] is True
    config = APISettings.model_construct(**state["settings"])
    client = realtime_redis_client(config)
    assert client.ping()
    namespace = "zelinx:events:labtest:" + uuid.uuid4().hex + ":"
    monkeypatch.setattr("api.events.redis_estate_journal.PREFIX", namespace + "estate:")
    monkeypatch.setattr("api.events.redis_sync.EVENT_STREAM", namespace + "global")
    monkeypatch.setattr("api.events.redis_sync.EVENT_SEQUENCE", namespace + "sequence")
    monkeypatch.setattr("api.events.redis_sync.CHANNEL", namespace + "channel")
    lab = Lab(config, state, client, namespace)
    yield lab
    # Discover afresh after promotion rather than deleting through an old
    # primary connection. Only this test's namespace is removed.
    with lab.operator(lab.master()) as admin:
        keys = list(admin.scan_iter(match=namespace + "*"))
        if keys:
            admin.delete(*keys)
    client.close()


def test_live_tls_acl_and_real_command_readiness(lab):
    assert lab.client.ping()
    probe_journal_commands(lab.client)
    with pytest.raises(redis.exceptions.NoPermissionError):
        lab.client.get("unrelated-private-key")
    with pytest.raises(redis.exceptions.NoPermissionError):
        lab.client.config_get("*")
    with pytest.raises(redis.exceptions.NoPermissionError):
        lab.client.publish("foreign-channel", "not-allowed")
    # ACL DRYRUN is privileged and does not execute the destructive command.
    with lab.operator(lab.master()) as admin:
        verdict = admin.acl_dryrun("replay", "FLUSHALL")
        assert "no permissions" in str(verdict).lower()


@pytest.mark.parametrize("fault", ["password", "untrusted-ca", "hostname"])
def test_bad_credentials_or_unverified_server_cannot_connect(lab, fault):
    config = lab.config.model_copy(update={"REDIS_SENTINELS": "", "REDIS_SENTINEL_MASTER": ""})
    if fault == "password":
        config.REDIS_URL = config.REDIS_URL.replace(urlsplit(config.REDIS_URL).password, "wrong-password")
    elif fault == "untrusted-ca":
        config.REDIS_CA_CERTS = "/dev/null"
    else:
        config.REDIS_URL = config.REDIS_URL.replace("127.0.0.1", "localhost")
    client = realtime_redis_client(config)
    try:
        with pytest.raises((redis.exceptions.RedisError, OSError)):
            client.ping()
    finally:
        client.close()


def test_ping_and_read_acl_do_not_prove_write_readiness(lab):
    config = lab.config.model_copy(update={"REDIS_SENTINELS": "", "REDIS_SENTINEL_MASTER": ""})
    config.REDIS_URL = f"rediss://limited:{lab.state['passwords']['limited']}@127.0.0.1:{lab.master()}/0"
    client = realtime_redis_client(config)
    bus = EventBus()
    sync = start_redis_federation(client, bus, required=True)
    try:
        assert client.ping() and sync is not None and not sync.ready
        with pytest.raises(RuntimeError):
            bus.publish("unaccepted", {}, tenant_id="a")
        assert not bus._history
    finally:
        sync.stop()
        client.close()


def test_acl_revocation_after_startup_refuses_append_without_local_success(lab):
    bus = EventBus()
    sync = start_redis_federation(lab.client, bus, required=True)
    try:
        assert sync.ready
        bus.publish("accepted", {"n": 1}, tenant_id="a")
        with lab.operator(lab.master()) as admin:
            admin.acl_setuser("replay", enabled=True, commands=["-xadd"])
            try:
                with pytest.raises(RuntimeError):
                    bus.publish("refused", {"n": 2}, tenant_id="a")
            finally:
                admin.acl_setuser("replay", enabled=True, commands=["+xadd"])
        bus.publish("accepted", {"n": 3}, tenant_id="a")
        page = bus.estate_page("a")
        assert [e["payload"]["n"] for e in page["events"]] == [1, 3]
        assert [e["id"] for e in page["events"]] == [1, 2]
        assert len(bus._history) == 2
    finally:
        sync.stop()


def wait_for_promotion(lab, previous):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        master = lab.master()
        if master != previous:
            # Discovery is eventually consistent. A single Sentinel announcing
            # a promotion does not prove the data clients have left the old
            # primary. Require converged discovery and actual role changes.
            converged = True
            for port in lab.state["sentinel_ports"]:
                with lab.operator(port) as sentinel:
                    converged &= int(sentinel.sentinel_get_master_addr_by_name("estate-lab")[1]) == master
            try:
                with lab.operator(previous) as old:
                    demoted = old.info("replication")["role"] != "master"
            except redis.ConnectionError:
                demoted = True
            with lab.operator(master) as admin:
                replication = admin.info("replication")
                if (
                    converged
                    and demoted
                    and replication["role"] == "master"
                    and replication.get("min_slaves_good_slaves", 0) >= 1
                ):
                    return master
        time.sleep(0.2)
    pytest.fail("No promoted primary with a connected replica within the bounded lab deadline")


@pytest.mark.parametrize("action", ["sentinel-failover", "primary-shutdown"])
def test_promotion_resets_frozen_cursor_and_preserves_replicated_estate(lab, action):
    bus = EventBus()
    sync = start_redis_federation(lab.client, bus, required=True)
    try:
        assert sync.ready
        for n in range(25):
            bus.publish("own", {"n": n}, tenant_id="a")
        for n in range(60):
            bus.publish("foreign", {"private": n}, tenant_id="b")
        first = bus.estate_page("a", limit=7)
        previous = lab.master()
        # A measured replication barrier for this experiment only. This does
        # NOT change normal journal acknowledgements to quorum commits.
        with lab.operator(previous) as admin:
            # WAIT refers to this connection's last write: write a marker on
            # that connection AFTER all test events, then wait on its offset.
            admin.set(lab.namespace + "barrier", "replicate-through-here")
            assert admin.wait(2, 5000) == 2
            if action == "primary-shutdown":
                admin.shutdown(nosave=True)
        if action == "sentinel-failover":
            with lab.operator(lab.state["sentinel_ports"][0]) as sentinel:
                sentinel.sentinel_failover("estate-lab")
        promoted = wait_for_promotion(lab, previous)
        assert promoted != previous
        lab.client.connection_pool.disconnect()
        restarted = EventBus()
        restarted.set_estate_history(RedisEstateJournal(lab.client).page)
        # Promotion can roll back asynchronous replication. Never continue a
        # frozen snapshot under the previous primary's cursor, even when this
        # particular fixture used a measured replication barrier.
        with pytest.raises(ReplayError, match="epoch changed"):
            restarted.estate_page("a", first["next_cursor"], 7)
        cursor = None
        seen = []
        while True:
            page = restarted.estate_page("a", cursor, 7)
            assert not page["retention_gap"] and page["epoch"] != first["epoch"]
            seen.extend(e["payload"]["n"] for e in page["events"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        assert seen == list(range(25))
        # A fresh connection discovers the promoted master for new writes.
        bus.publish("after-promotion", {"n": 25}, tenant_id="a")
        assert restarted.estate_page("a", cursor)["events"][0]["payload"]["n"] == 25
    finally:
        sync.stop()

"""Storage topology and replicated writes: HA as a checked claim.

The review's item is that an object store in the same failure domain as the
primary is not a backup. These tests pin the difference between "two copies
exist" and "two copies survive one event", and pin that a replica which accepts a
write and returns different bytes is a failed replica.
"""

from __future__ import annotations

import json

import pytest

from devsecops.storage_topology import (ReplicatedStore, StoreSite, placement, shared_domains,
                                        topology_from_env)


class _Memory:
    def __init__(self, *, corrupt: bool = False, fail: bool = False):
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, dict] = {}
        self.corrupt = corrupt
        self.fail = fail

    def put(self, key, blob):
        if self.fail:
            raise OSError("volume is gone")
        self.blobs[key] = blob + (b"tampered" if self.corrupt else b"")

    def put_manifest(self, key, manifest):
        if self.fail:
            raise OSError("volume is gone")
        self.manifests[key] = manifest

    def get(self, key):
        return self.blobs[key]

    def delete(self, key):
        self.blobs.pop(key, None)
        self.manifests.pop(key, None)

    def list_manifests(self):
        return list(self.manifests.values())


PRIMARY = StoreSite(name="primary", provider="aws", region="eu-west-1", zone="a")
REPLICA_SAME_REGION = StoreSite(name="replica", provider="aws", region="eu-west-1", zone="b")
REPLICA_OTHER_REGION = StoreSite(name="dr", provider="aws", region="eu-central-1")
OTHER_PROVIDER = StoreSite(name="dr", provider="azure", region="eu-west-1")


def test_shared_domains_names_only_axes_both_sites_declare():
    assert shared_domains(PRIMARY, REPLICA_SAME_REGION) == ["provider", "region"]
    assert shared_domains(PRIMARY, REPLICA_OTHER_REGION) == ["provider"]
    # `provider` defaults to "local", which is itself a claim: two sites that
    # never said where they are are treated as one domain, not as separate
    assert shared_domains(StoreSite(name="a"), StoreSite(name="b")) == ["provider"]


def test_same_region_replica_is_refused_with_the_reason():
    verdict = placement([PRIMARY, REPLICA_SAME_REGION])
    assert verdict["verdict"] == "REFUSE"
    assert "share region" in verdict["statement"]
    assert "one event removes both copies" in verdict["statement"]
    assert verdict["pairs"][0]["offending"] == ["region"]


def test_replica_in_another_region_is_allowed(): 
    verdict = placement([PRIMARY, REPLICA_OTHER_REGION])
    assert verdict["verdict"] == "ALLOW"
    assert verdict["statement"] == "2 site(s), separated on region"


def test_separation_can_be_required_on_more_than_region():
    # a second provider in the *same* region is still one regional outage
    assert placement([PRIMARY, OTHER_PROVIDER], require=("region", "provider"))["verdict"] == "REFUSE"
    assert placement([PRIMARY, OTHER_PROVIDER], require=("provider",))["verdict"] == "ALLOW"
    assert placement([PRIMARY, REPLICA_SAME_REGION], require=("zone",))["verdict"] == "ALLOW"
    assert placement([PRIMARY, REPLICA_SAME_REGION],
                     require=("provider", "zone"))["verdict"] == "REFUSE"   # same provider
    assert placement([PRIMARY, StoreSite(name="x", provider="aws", region="eu-west-1")],
                     require=("zone",))["verdict"] == "REFUSE"   # zone undeclared on both


def test_one_site_is_not_redundant_by_definition():
    verdict = placement([PRIMARY])
    assert verdict["verdict"] == "REFUSE"
    assert "at least 2 are required" in verdict["statement"]


def test_no_sites_is_refused_rather_than_trivially_satisfied():
    assert placement([])["verdict"] == "REFUSE"


def test_duplicate_site_names_are_refused():
    verdict = placement([PRIMARY, StoreSite(name="primary", region="eu-central-1")])
    assert verdict["verdict"] == "REFUSE"
    assert "share a name" in verdict["statement"]


def test_undeclared_topology_is_a_state_not_a_pass():
    result = topology_from_env({})
    assert result["verdict"] == "UNDECLARED"
    assert result["declared"] is False
    assert "UNDECLARED" in result["statement"]
    assert "cannot be evidenced" in result["reasons"][0]


def test_invalid_topology_reports_that_it_cannot_be_read():
    result = topology_from_env({"SBOM_STORAGE_SITES": "{not json"})
    assert result["verdict"] == "INVALID"


def test_topology_from_env_reads_named_sites():
    env = {"SBOM_STORAGE_SITES": json.dumps([
        {"name": "primary", "provider": "aws", "region": "eu-west-1"},
        {"name": "dr", "provider": "aws", "region": "eu-central-1"}])}
    result = topology_from_env(env)
    assert result["verdict"] == "ALLOW" and result["declared"] is True
    assert [site["name"] for site in result["sites"]] == ["primary", "dr"]


def test_topology_accepts_a_sites_object():
    env = {"SBOM_STORAGE_SITES": json.dumps({"sites": [
        {"name": "primary", "region": "eu-west-1"}, {"name": "dr", "region": "us-east-1"}]})}
    assert topology_from_env(env)["verdict"] == "ALLOW"


def _store(*, replica=None, **kwargs):
    replicas = replica if replica is not None else _Memory()
    store = ReplicatedStore(sites=(PRIMARY, REPLICA_OTHER_REGION),
                            backends={"primary": _Memory(**kwargs), "dr": replicas})
    return store, replicas


def test_put_writes_every_site_and_verifies_each_digest():
    store, replica = _store()
    result = store.put("k", b"payload")
    assert result["acknowledged"] is True
    assert sorted(result["verified"]) == ["dr", "primary"]
    assert result["mismatched"] == []
    assert replica.blobs["k"] == b"payload"


def test_a_replica_that_returns_different_bytes_is_not_a_copy():
    store, _ = _store(replica=_Memory(corrupt=True))
    with pytest.raises(IOError):
        store.put("k", b"payload")
    health = store.health()
    assert health["verdict"] == "DEGRADED"
    assert "dr" in health["degraded"]
    assert health["health"]["dr"]["failures"] == 1


def test_two_sites_need_both_and_say_so():
    store = ReplicatedStore(sites=(PRIMARY, REPLICA_OTHER_REGION),
                            backends={"primary": _Memory(), "dr": _Memory(fail=True)})
    # with two sites the quorum is two: one copy is not a replica
    with pytest.raises(IOError, match="reached 1 verified site"):
        store.put("k", b"payload")
    assert store.health()["degraded"] == ["dr"]


def test_three_sites_survive_one_bad_replica():
    sites = (PRIMARY, REPLICA_OTHER_REGION, StoreSite(name="cold", region="us-east-1"))
    store = ReplicatedStore(sites=sites, backends={"primary": _Memory(), "dr": _Memory(),
                                                   "cold": _Memory(fail=True)})
    result = store.put("k", b"payload")
    assert result["acknowledged"] is True and result["quorum"] == 2
    assert store.health()["verdict"] == "DEGRADED"


def test_below_quorum_raises_rather_than_acknowledging():
    sites = (PRIMARY, REPLICA_OTHER_REGION, StoreSite(name="cold", region="us-east-1"))
    store = ReplicatedStore(sites=sites, backends={"primary": _Memory(fail=True),
                                                   "dr": _Memory(fail=True),
                                                   "cold": _Memory()})
    with pytest.raises(IOError, match="below the quorum"):
        store.put("k", b"payload")


def test_manifests_are_written_to_every_site():
    store, replica = _store()
    result = store.put_manifest("m", {"storage_key": "m"})
    assert result["acknowledged"] is True
    assert replica.manifests["m"] == {"storage_key": "m"}


def test_reading_and_deleting_go_through_the_healthy_site():
    store, _ = _store()
    store.put("k", b"payload")
    assert store.get("k") == b"payload"
    store.delete("k")
    assert store.list_manifests() == []


def test_failed_replica_list_cannot_be_reported_as_no_manifests():
    class FailedList(_Memory):
        def list_manifests(self):
            raise OSError("test-only replica unavailable")

    store = ReplicatedStore(sites=(PRIMARY, REPLICA_OTHER_REGION),
                            backends={"primary": _Memory(), "dr": FailedList()})
    with pytest.raises(IOError, match="manifest listing was incomplete"):
        store.list_manifests()
    assert ReplicatedStore(sites=(PRIMARY,), backends={"primary": _Memory()}).list_manifests() == []


def test_an_unconfigured_backend_is_a_failed_site_not_a_silent_success():
    store = ReplicatedStore(sites=(PRIMARY,), backends={})
    with pytest.raises(IOError, match="below the quorum"):
        store.put("k", b"payload")
    assert store.health()["health"]["primary"]["failures"] == 1

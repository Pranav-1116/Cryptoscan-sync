"""The bank-side agent: transport what the collectors wrote, and post only a change."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import runner as agent_runner


def _plane(plane: str, *, assets: int = 1, expected: int | None = 1, collected: int | None = 1) -> dict:
    return {
        "plane": plane,
        "estate": "payments",
        "scope": "production",
        "assets": [
            {"ref": f"{plane}-{index}", "type": "HOST", "name": f"{plane}-{index}"}
            for index in range(assets)
        ],
        "evidence": [
            {
                "source": plane.lower(),
                "evidence_type": "STATIC_OBSERVED",
                "target": f"{plane}-{index}",
                "layer": "PLATFORM",
                "facts": {"hostname": f"{plane}-{index}"},
            }
            for index in range(assets)
        ],
        "coverage": {"expected": expected, "collected": collected},
    }


@pytest.fixture
def source_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "observations"
    directory.mkdir()
    (directory / "linux-hosts.json").write_text(json.dumps(_plane("Linux hosts", assets=2, expected=2)))
    (directory / "network.json").write_text(json.dumps(_plane("Network", assets=1, expected=1)))
    return directory


class FakePlane:
    """Records every POST and answers with the platform's shape."""

    def __init__(self, status: int = 201, body: dict | None = None) -> None:
        self.status = status
        self.body = body if body is not None else {"state": "CHANGED", "stored": True, "projection_id": "proj-1"}
        self.calls: list[tuple[str, dict, bytes]] = []

    def __call__(self, url, headers, body, timeout):  # noqa: ANN001
        self.calls.append((url, dict(headers), body))
        return self.status, self.body


def _agent(source_dir: Path, transport, **overrides) -> agent_runner.Agent:
    config = agent_runner.AgentConfig(
        server="https://control-plane.bank.internal",
        token="session-token",
        source_dir=source_dir,
        **overrides,
    )
    return agent_runner.Agent(config, transport=transport)


def test_the_agent_merges_planes_into_one_observation(source_dir):
    observation = agent_runner.DirectorySource(source_dir).collect()

    assert len(observation["assets"]) == 3
    assert len(observation["evidence"]) == 3
    assert {row["plane"] for row in observation["coverage"]} == {"Linux hosts", "Network"}
    assert all(row["state"] == "COMPLETE" for row in observation["collectors"])


def test_an_unreadable_collector_file_is_a_failed_plane_not_a_smaller_estate(source_dir):
    (source_dir / "broken.json").write_text("{not json")

    observation = agent_runner.DirectorySource(source_dir).collect()

    failed = [row for row in observation["collectors"] if row["state"] == "FAILED"]
    assert [row["plane"] for row in failed] == ["broken"]
    assert "could not be read" in failed[0]["reason"]
    assert observation["failures"][0]["plane"] == "broken"
    # the readable planes still arrive
    assert len(observation["assets"]) == 3


def test_a_collector_that_states_no_coverage_is_unknown_not_complete(source_dir):
    (source_dir / "windows.json").write_text(json.dumps({"plane": "Windows", "assets": [], "evidence": []}))

    observation = agent_runner.DirectorySource(source_dir).collect()

    row = next(item for item in observation["coverage"] if item["plane"] == "Windows")
    assert row["expected"] is None
    assert "UNKNOWN" in row["reason"]


def test_an_empty_observation_is_never_pushed(tmp_path):
    transport = FakePlane()
    directory = tmp_path / "empty"
    directory.mkdir()
    (directory / "linux-hosts.json").write_text(json.dumps({"plane": "Linux hosts", "assets": [], "evidence": []}))

    result = _agent(directory, transport).run_once()

    assert result["state"] == agent_runner.NOTHING_COLLECTED
    assert result["posted"] is False
    assert transport.calls == []


def test_the_first_observation_is_pushed_with_its_state_hash(source_dir):
    transport = FakePlane()

    result = _agent(source_dir, transport).run_once()

    assert result["state"] == agent_runner.PUSHED
    assert result["posted"] is True
    url, headers, body = transport.calls[0]
    assert url.endswith("/api/v1/ingestion/observations")
    assert headers["Authorization"] == "Bearer session-token"
    document = json.loads(body)
    assert document["state_hash"] == result["state_hash"]
    assert len(document["assets"]) == 3


def test_an_unchanged_estate_is_not_posted_at_all(source_dir):
    transport = FakePlane()
    agent = _agent(source_dir, transport)

    first = agent.run_once()
    second = agent.run_once()

    assert first["state"] == agent_runner.PUSHED
    assert second["state"] == agent_runner.UNCHANGED
    assert second["posted"] is False
    assert len(transport.calls) == 1, "the agent uploaded an unchanged estate"


def test_a_changed_estate_is_posted_again(source_dir):
    transport = FakePlane()
    agent = _agent(source_dir, transport)
    agent.run_once()

    (source_dir / "linux-hosts.json").write_text(
        json.dumps(_plane("Linux hosts", assets=3, expected=3, collected=3))
    )
    result = agent.run_once()

    assert result["state"] == agent_runner.PUSHED
    assert len(transport.calls) == 2


def test_a_refused_observation_is_not_retried(source_dir):
    transport = FakePlane(status=401, body={"detail": "session expired"})
    agent = _agent(source_dir, transport, retries=3)

    result = agent.run_once()

    assert result["state"] == agent_runner.REFUSED
    assert len(transport.calls) == 1
    assert "not retried" in result["note"]


def test_a_failed_push_does_not_advance_the_hash_so_the_change_is_retried(source_dir, tmp_path):
    state_file = tmp_path / "agent-state.json"
    failing = FakePlane(status=503, body={"detail": "unavailable"})
    agent = _agent(source_dir, failing, retries=0, state_path=state_file)

    failed = agent.run_once()
    assert failed["state"] == agent_runner.FAILED
    assert not state_file.exists(), "a failed push wrote a state hash and would swallow the change"

    healthy = FakePlane()
    retried = _agent(source_dir, healthy, state_path=state_file).run_once()
    assert retried["state"] == agent_runner.PUSHED
    assert len(healthy.calls) == 1


def test_the_last_hash_survives_a_restart(source_dir, tmp_path):
    state_file = tmp_path / "agent-state.json"
    first = _agent(source_dir, FakePlane(), state_path=state_file).run_once()

    restarted = _agent(source_dir, FakePlane(), state_path=state_file).run_once()

    assert first["state"] == agent_runner.PUSHED
    assert restarted["state"] == agent_runner.UNCHANGED
    assert json.loads(state_file.read_text())["last_hash"] == first["state_hash"]


def test_the_agent_signs_its_observation_when_a_key_is_given(source_dir, tmp_path):
    from shared_models import release_signature

    keys = release_signature.generate_keypair(tmp_path / "keys", name="collector")
    transport = FakePlane()

    _agent(source_dir, transport, sign_key=keys["private_key"]).run_once()

    document = json.loads(transport.calls[0][2])
    assert document["signature"]["key_id"].startswith("ed25519:")
    # verified exactly as the platform verifies it: over ingestion.signed_document(body),
    # not over the posted body (which also carries state_hash)
    from api.routers.ingestion import LiveObservationRequest, signed_document

    rebuilt = signed_document(LiveObservationRequest(**document))
    verdict = release_signature.verify_document(
        {**rebuilt, "signature": document["signature"]},
        trusted_key=release_signature.load_public_key(keys["public_key"]),
    )
    assert verdict["status"] == release_signature.VALID


def test_a_source_that_raises_is_the_callers_problem_not_a_silent_empty_push(tmp_path):
    class Exploding:
        def collect(self):
            raise RuntimeError("collector directory vanished")

    agent = agent_runner.Agent(
        agent_runner.AgentConfig(server="https://control-plane.bank.internal", source_dir=tmp_path),
        source=Exploding(),
        transport=FakePlane(),
    )
    with pytest.raises(RuntimeError):
        # the source contract is "return an observation"; a broken source must not be
        # converted into an empty observation, which the platform would read as a change
        agent.run_once()


def test_the_cli_refuses_without_a_control_plane(capsys):
    code = agent_runner.main(["--source", ".", "--once"])

    assert code == 3
    assert "REFUSED" in capsys.readouterr().out

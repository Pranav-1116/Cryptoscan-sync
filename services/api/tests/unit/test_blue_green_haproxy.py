"""The reference second blue-green adapter: HAProxy via its runtime API.

The runbook promised "a bank running F5/HAProxy writes one adapter with
the same five methods" — this file pins the one the repo now ships.
The fake pool speaks the same command vocabulary as the real admin
socket (enable/disable server, set server ... weight/state, show stat),
so the tests pin the command sequences and the read-back parsing, not a
parallel universe. The honesty rules carry over unchanged: an
unreachable socket raises (never fakes healthy), and a split pool is
named, never guessed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
_spec = importlib.util.spec_from_file_location(
    "blue_green", REPO / "scripts" / "blue_green.py")
blue_green = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(blue_green)
BlueGreen = blue_green.BlueGreen
HAProxyDriver = blue_green.HAProxyDriver

HEADER = ("# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,"
          "dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight")


class FakeHAProxyPool:
    """A tiny in-memory HAProxy: stateful, command-driven, log-keeping."""

    def __init__(self, **states):
        self.servers = {
            "api-blue": {"status": "UP", "weight": 100},
            "api-green": {"status": "MAINT", "weight": 0},
        }
        self.servers.update(states)
        self.log: list[str] = []

    def connect(self):
        pool = self

        class FakeSocket:
            def __init__(self):
                self._buf = b""

            def sendall(self, data):
                self._buf = pool.respond(data.decode().strip()).encode()

            def recv(self, _n):
                out, self._buf = self._buf, b""
                return out

            def close(self):
                pass

        return FakeSocket()

    def _stat_csv(self) -> str:
        lines = [HEADER]
        for name, state in self.servers.items():
            lines.append(f"cryptoscan-api,{name},0,0,0,0,,0,0,0,0,0,0,0,0,0,0,"
                         f"{state['status']},{state['weight']}")
        return "\n".join(lines) + "\n"

    def respond(self, cmd: str) -> str:
        self.log.append(cmd)
        parts = cmd.split()
        if cmd == "show stat":
            return self._stat_csv()
        if parts[:2] == ["enable", "server"]:
            self.servers[parts[2].split("/", 1)[1]]["status"] = "UP"
        elif parts[:2] == ["disable", "server"]:
            self.servers[parts[2].split("/", 1)[1]]["status"] = "MAINT"
        elif parts[:2] == ["set", "server"]:
            name = parts[2].split("/", 1)[1]
            if parts[3] == "weight":
                self.servers[name]["weight"] = int(parts[4])
            elif parts[3] == "state":
                self.servers[name]["status"] = {
                    "ready": "UP", "drain": "DRAIN", "maint": "MAINT"}[parts[4]]
        return ""


def _driver(pool: FakeHAProxyPool) -> HAProxyDriver:
    return HAProxyDriver(connect=pool.connect)


class TestTheAdapterSpeaksTheRuntimeAPI:
    def test_start_puts_the_slot_in_the_pool_at_zero_weight(self):
        pool = FakeHAProxyPool()
        _driver(pool).start("green")
        assert pool.log == [
            "enable server cryptoscan-api/api-green",
            "set server cryptoscan-api/api-green weight 0",
        ]
        # health-checked and silent: green is UP but holds no traffic
        assert pool.servers["api-green"] == {"status": "UP", "weight": 0}

    def test_stop_takes_the_slot_out_of_rotation(self):
        pool = FakeHAProxyPool()
        _driver(pool).stop("blue")
        assert pool.log == ["disable server cryptoscan-api/api-blue"]
        assert pool.servers["api-blue"]["status"] == "MAINT"

    def test_health_reads_the_pool_never_guesses(self):
        pool = FakeHAProxyPool(**{
            "api-green": {"status": "UP", "weight": 0}})
        assert _driver(pool).health("green") is True
        pool.servers["api-green"]["status"] = "DRAIN"
        assert _driver(pool).health("green") is False

    def test_activate_gives_the_weight_and_drains_the_other(self):
        pool = FakeHAProxyPool(**{
            "api-green": {"status": "UP", "weight": 0}})
        _driver(pool).activate("green")
        assert pool.log == [
            "set server cryptoscan-api/api-green state ready",
            "set server cryptoscan-api/api-green weight 100",
            "set server cryptoscan-api/api-blue weight 0",
            "set server cryptoscan-api/api-blue state drain",
        ]
        assert pool.servers["api-green"]["weight"] == 100
        assert pool.servers["api-blue"] == {"status": "DRAIN", "weight": 0}

    def test_active_reads_back_the_single_slot_holding_traffic(self):
        pool = FakeHAProxyPool()
        assert _driver(pool).active() == "blue"
        pool.servers["api-blue"]["weight"] = 0
        assert _driver(pool).active() is None

    def test_a_split_pool_is_named_not_guessed(self):
        pool = FakeHAProxyPool(**{
            "api-green": {"status": "UP", "weight": 50}})
        with pytest.raises(RuntimeError, match="split pool"):
            _driver(pool).active()

    def test_an_unreachable_socket_raises_never_fakes(self):
        def dead():
            raise ConnectionRefusedError("no admin socket")

        driver = HAProxyDriver(connect=dead)
        with pytest.raises(RuntimeError, match="unreachable"):
            driver.health("blue")  # never True from silence


class TestTheStateMachineRunsOverTheAdapter:
    def test_prepare_activate_verify_flip_for_real(self):
        pool = FakeHAProxyPool(**{
            "api-green": {"status": "MAINT", "weight": 0}})
        orchestrator = BlueGreen(_driver(pool))

        prepared = orchestrator.prepare("green")
        assert prepared["healthy"] is True
        assert pool.servers["api-green"] == {"status": "UP", "weight": 0}

        flipped = orchestrator.activate("green")
        assert flipped["previous"] == "blue"
        assert flipped["active"] == "green"
        assert _driver(pool).active() == "green"

        assert orchestrator.verify("green")["verified"] is True

    def test_an_unhealthy_activation_is_refused_and_a_bad_verify_rolls_back(self):
        pool = FakeHAProxyPool(**{
            "api-green": {"status": "UP", "weight": 0}})
        orchestrator = BlueGreen(_driver(pool))

        # green dies between prepare and activate
        pool.servers["api-green"]["status"] = "DOWN"
        refused = orchestrator.activate("green")
        assert "refused" in refused
        assert pool.servers["api-blue"]["weight"] == 100  # untouched

        # green claims healthy, takes the flip, then fails verify
        pool.servers["api-green"]["status"] = "UP"
        orchestrator.activate("green")
        pool.servers["api-green"]["status"] = "DOWN"
        plan = orchestrator.verify("green")
        assert plan["verified"] is False
        assert plan["rolled_back_to"] == "blue"
        assert _driver(pool).active() == "blue"  # the flip was undone

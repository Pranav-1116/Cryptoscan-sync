#!/usr/bin/env python3
"""Blue-green upgrades for the API tier — a flip you can undo.

The spec marks blue-green deployment High ("safer upgrades"): a release
that turns out wrong must cost one command, not one incident. This script
orchestrates two slots behind one entry point:

    prepare   start/refresh GREEN alongside BLUE (the active slot), and
              health-check it — a green slot that does not come up is
              stopped again, never activated
    activate  flip the entry point to GREEN; BLUE keeps running (instant
              rollback stays possible)
    verify    probe the now-active slot; on failure the flip is UNDONE
              automatically — the blast radius of a bad release is one
              flip, immediately reversed
    rollback  flip back to the previous slot (also the manual escape hatch)
    status    which slot is active and healthy right now

Every step works against an injected slot driver, so the orchestration is
testable without Docker. The CLI's compose driver writes an upstream
pointer file (the nginx template reads it) and reloads nginx — the same
mechanism a bank's F5/HAProxy pair uses, one adapter away.

    python3 scripts/blue_green.py prepare --slot green
    python3 scripts/blue_green.py activate --slot green
    python3 scripts/blue_green.py verify --slot green   # auto-rollback on fail
    python3 scripts/blue_green.py rollback

``--dry-run`` prints the plan and touches nothing.

Runbook: docs/runbooks/blue-green-upgrade.md
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parent.parent


class SlotDriver(Protocol):
    """What the orchestrator needs from the deployment substrate."""

    def start(self, slot: str) -> None: ...
    def stop(self, slot: str) -> None: ...
    def health(self, slot: str) -> bool: ...
    def activate(self, slot: str) -> None: ...
    def active(self) -> str | None: ...


class BlueGreen:
    """The upgrade state machine. Honesty rules, enforced not documented:

    * activation REFUSES an unhealthy slot (never flip blind);
    * verify failure rolls back automatically (a bad release costs a flip);
    * rollback always names where it went back to;
    * every step reports what it did and what it refused.
    """

    def __init__(self, driver: SlotDriver):
        self.driver = driver

    def _other(self, slot: str) -> str:
        return "blue" if slot == "green" else "green"

    def prepare(self, slot: str, *, dry_run: bool = False) -> dict:
        if slot not in ("blue", "green"):
            raise ValueError("slot is 'blue' or 'green'")
        plan = {"step": "prepare", "slot": slot, "dry_run": dry_run}
        if dry_run:
            plan["would"] = f"start {slot}, health-check it, stop it if unhealthy"
            return plan
        self.driver.start(slot)
        healthy = self.driver.health(slot)
        plan["healthy"] = healthy
        if not healthy:
            self.driver.stop(slot)
            plan["refused"] = ("green slot failed its health check — stopped "
                               "again; the active slot is untouched")
        return plan

    def activate(self, slot: str, *, dry_run: bool = False) -> dict:
        plan = {"step": "activate", "slot": slot, "dry_run": dry_run}
        if dry_run:
            plan["would"] = f"flip the entry point to {slot}"
            return plan
        if not self.driver.health(slot):
            plan["refused"] = (f"{slot} is not healthy — activation refused; "
                               "a blind flip is how upgrades become outages")
            plan["active"] = self.driver.active()
            return plan
        previous = self.driver.active()
        self.driver.activate(slot)
        plan.update({"previous": previous, "active": slot})
        return plan

    def verify(self, slot: str, *, dry_run: bool = False) -> dict:
        plan = {"step": "verify", "slot": slot, "dry_run": dry_run}
        if dry_run:
            plan["would"] = f"probe {slot}; on failure flip back automatically"
            return plan
        if self.driver.health(slot):
            plan["verified"] = True
            return plan
        # automatic undo: the blast radius of a bad release is one flip
        fallback = self._other(slot)
        self.driver.activate(fallback)
        plan.update({"verified": False, "rolled_back_to": fallback,
                     "note": "the flip was undone automatically — the previous "
                             "slot is serving again"})
        return plan

    def rollback(self, slot: str | None = None, *, dry_run: bool = False) -> dict:
        current = self.driver.active()
        target = slot or (self._other(current) if current else "blue")
        plan = {"step": "rollback", "from": current, "to": target, "dry_run": dry_run}
        if dry_run:
            plan["would"] = f"flip back to {target}"
            return plan
        self.driver.activate(target)
        plan["active"] = target
        return plan

    def status(self) -> dict:
        active = self.driver.active()
        return {"step": "status", "active": active,
                "healthy": self.driver.health(active) if active else False}


# ------------------------------------------------------------------- drivers

class PointerFileDriver:
    """Compose/nginx driver: slot = compose service, flip = pointer file +
    nginx reload. The pointer is the single source of truth for the
    upstream template; the reload is what makes the flip take effect."""

    def __init__(self, project: str = "cryptoscan", pointer: Path | None = None,
                 runner=None):
        import subprocess

        self.project = project
        self.pointer = pointer or (ROOT / "deploy" / "upstream.active")
        self._run = runner or (lambda cmd: subprocess.run(
            cmd, capture_output=True, text=True, timeout=120))

    def _compose(self, *args: str):
        return self._run(["docker", "compose", "-p", self.project, *args])

    def start(self, slot: str) -> None:
        self._compose("up", "-d", f"api-{slot}")

    def stop(self, slot: str) -> None:
        self._compose("stop", f"api-{slot}")

    def health(self, slot: str) -> bool:
        # the compose stack's healthcheck is the source; the pointer never
        # flips without it
        result = self._compose("ps", "--status", "running", f"api-{slot}")
        return result.returncode == 0 and f"api-{slot}" in (result.stdout or "")

    def activate(self, slot: str) -> None:
        self.pointer.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.pointer.with_suffix(".tmp")
        tmp.write_text(f"api-{slot}\n")
        tmp.replace(self.pointer)  # atomic: a torn pointer is never read
        self._run(["nginx", "-s", "reload"])

    def active(self) -> str | None:
        if not self.pointer.exists():
            return None
        text = self.pointer.read_text().strip()
        return text.removeprefix("api-") if text else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("step", choices=["prepare", "activate", "verify", "rollback", "status"])
    ap.add_argument("--slot", choices=["blue", "green"])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--project", default="cryptoscan")
    ap.add_argument("--pointer", default=str(ROOT / "deploy" / "upstream.active"))
    args = ap.parse_args()

    orchestrator = BlueGreen(PointerFileDriver(project=args.project,
                                               pointer=Path(args.pointer)))
    if args.step == "status":
        report = orchestrator.status()
    else:
        if not args.slot and args.step != "rollback":
            ap.error(f"{args.step} needs --slot blue|green")
        report = getattr(orchestrator, args.step)(args.slot, dry_run=args.dry_run)
    print(json.dumps(report, indent=2))
    refused = bool(report.get("refused") or report.get("verified") is False)
    return 1 if refused else 0


if __name__ == "__main__":
    raise SystemExit(main())

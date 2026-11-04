#!/usr/bin/env python3
"""Non-destructive scratch observer for OPERATOR-controlled Redis fault exercises.

Never kills/promotes/partitions a server, changes ACLs, alters config, or touches
bank queues/state. The approved operator performs and witnesses the fault.
Connection secrets come only from deployment env (shared verified role factory).
Output is retained measurement evidence, NOT self-issued deployment acceptance.

prepare writes/fsyncs an acknowledgement ledger. After the approved fault, finish
checks those exact prior IDs and measures scratch recovery load. A new snapshot
cannot replace missing old acknowledgements. This single observer cannot prove
server power-loss behavior or events acknowledged between Redis ACK and local
journal fsync if the OBSERVER itself is killed; use an independent durable witness.
"""
import argparse
import json
import os
import re
from pathlib import Path
import sys
import time
import uuid
from types import SimpleNamespace
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
for directory in sorted(ROOT.glob("shared/*/")):
    sys.path.insert(0, str(directory))
from shared_models.assurance import RedisMeasurement, REDIS_ROLES, REDIS_SCENARIOS  # noqa: E402
from shared_models.redis_connection import connection_settings, verified_redis_client, probe_role_commands  # noqa: E402
from shared_models.qualified_export import bounded_json  # noqa: E402


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def client(role):
    from shared_config import environment as platform_environment

    settings = SimpleNamespace(is_production=platform_environment.is_production(),
        **{name: os.getenv(name, "") for name in ("REDIS_URL", "REDIS_CA_CERTS", "REDIS_SENTINELS", "REDIS_SENTINEL_MASTER", "REDIS_SENTINEL_USERNAME", "REDIS_SENTINEL_PASSWORD")})
    return verified_redis_client(connection_settings(settings, role), decode_responses=True)


def write(c, role, root, token):
    if role == "queue":
        c.rpush(root + ":queue", token)
        c.expire(root + ":queue", 604800)
    elif role == "realtime":
        c.xadd(root + ":stream", {"event_id": token})
        c.expire(root + ":stream", 604800)
    elif role == "rate_limit":
        c.incr(root + ":" + token)
        c.expire(root + ":" + token, 604800)
    elif role == "health":
        c.ping()
    else:
        c.set(root + ":" + token, token, ex=604800)


def recover(c, role, root, ids):
    if role == "queue":
        present = set(c.lrange(root + ":queue", 0, 1001))
        return [i for i in ids if i in present]
    if role == "realtime":
        present = {values["event_id"] for _, values in c.xrange(root + ":stream", "-", "+", count=1001)}
        return [i for i in ids if i in present]
    if role == "health":
        return []
    present = []
    for identifier in ids:
        value = c.get(root + ":" + identifier)
        if value == ("1" if role == "rate_limit" else identifier):
            present.append(identifier)
    return present


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "finish"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--role", choices=REDIS_ROLES)
    parser.add_argument("--deployment-id")
    parser.add_argument("--topology-sha256")
    parser.add_argument("--events", type=int, default=20)
    parser.add_argument("--scenario", choices=REDIS_SCENARIOS)
    parser.add_argument("--fault-at", help="Actual witnessed UTC fault start; never inferred from promotion")
    parser.add_argument("--fault-witness")
    parser.add_argument("--evidence-ref")
    parser.add_argument("--load-seconds", type=float, default=5)
    parser.add_argument("--operations-per-second", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.events <= 1000 or not 1 <= args.load_seconds <= 300 or not 1 <= args.operations_per_second <= 1000:
        parser.error("events=1..1000, load-seconds=1..300, operations-per-second=1..1000")
    c = None
    try:
        if args.phase == "prepare":
            if not args.role or not args.deployment_id or not args.topology_sha256:
                parser.error("prepare requires role, deployment-id and topology-sha256")
            if len(args.topology_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in args.topology_sha256):
                parser.error("topology-sha256 must be the approved nonsecret topology/configuration digest")
            args.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
            root = "cryptoscan:qualification:recovery:" + uuid.uuid4().hex
            run = {"root": root, "role": args.role, "deployment_id": args.deployment_id,
                   "topology_sha256": args.topology_sha256, "prepared_at": now()}
            c = client(args.role)
            run["command_probe"] = probe_role_commands(c, args.role)
            save(args.directory / "run.json", run)
            with open(args.directory / "acknowledged.jsonl", "x", encoding="utf-8") as ledger:
                os.chmod(args.directory / "acknowledged.jsonl", 0o600)
                for number in range(args.events if args.role != "health" else 0):
                    token = str(uuid.uuid4())
                    write(c, args.role, root, token)
                    ledger.write(json.dumps({"event_id": token, "acknowledged_at": now()}) + "\n")
                    ledger.flush()
                    os.fsync(ledger.fileno())
            print("Prepared isolated scratch ledger; now perform ONLY the separately approved witnessed fault.")
            return 0
        if not all((args.scenario, args.fault_at, args.fault_witness, args.evidence_ref)):
            parser.error("finish requires scenario, actual fault-at, fault-witness and evidence-ref")
        run = bounded_json((args.directory / "run.json").read_bytes())
        if not isinstance(run, dict) or run.get("role") not in REDIS_ROLES or not re.fullmatch(r"cryptoscan:qualification:recovery:[0-9a-f]{32}", run.get("root", "")):
            raise ValueError("Refuse non-qualification namespace or unknown consumer role")
        raw = (args.directory / "acknowledged.jsonl").read_bytes()
        if len(raw) > 1048576:
            raise ValueError("Acknowledgement ledger bound")
        acknowledged = [bounded_json(line) for line in raw.splitlines()]
        c = client(run["role"])
        c.ping()
        recovered = recover(c, run["role"], run["root"], [a["event_id"] for a in acknowledged])
        recovered_at = now()  # verified read of the old IDs, not PING/promotion alone
        start, operations = time.monotonic(), 0
        next_op = start
        while time.monotonic() - start < args.load_seconds and operations < 100000:
            write(c, run["role"], run["root"] + ":load", "bounded-load-token")
            operations += 1
            next_op += 1 / args.operations_per_second
            time.sleep(max(0, next_op - time.monotonic()))
        measurement = {"deployment_id": run["deployment_id"], "topology_sha256": run["topology_sha256"],
            "scenario": args.scenario, "role": run["role"], "fault_at": args.fault_at,
            "recovered_at": recovered_at, "measured_until": now(), "acknowledged": acknowledged,
            "recovered_event_ids": recovered, "recovery_operations": operations,
            "fault_witness": args.fault_witness, "evidence_ref": args.evidence_ref,
            "evidence_blob_id": str(uuid.uuid4())}
        typed = RedisMeasurement.model_validate(measurement)
        save(args.directory / "measurement.json", {"measurement": typed.model_dump(mode="json", exclude={"evidence_blob_id"}),
            "observer": "redis_recovery_evidence/v1", "clock": "OPERATOR_OBSERVER_UTC_REQUIRES_CLOCK_QUALIFICATION",
            "command_probe": run["command_probe"], "deployment_acceptance": "SEPARATE_HUMAN_REVIEW_REQUIRED"})
        print("Retained measurement.json; upload as an evidence blob, register it against approved objectives, and obtain a separate human review.")
        return 0
    except Exception as exc:
        # Never echo Redis URLs/credentials or third-party exception messages.
        print(f"Evidence collection failed ({type(exc).__name__}); no qualification issued. Retain partial ledger and operator logs.", file=sys.stderr)
        return 1
    finally:
        if c is not None:
            c.close()


if __name__ == "__main__":
    raise SystemExit(main())

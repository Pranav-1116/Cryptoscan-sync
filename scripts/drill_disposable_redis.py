#!/usr/bin/env python3
"""Scratch-only Redis SIGKILL/RDB drill. Not deployment acceptance.

Only the explicitly authorized private Unix-socket lab is allowed. The server
is started/restarted separately by the operator. Never use deployment URLs.
Each role is a real Redis structure, but consumer integration is NOT implied.
"""
from _bootstrap import bootstrap
bootstrap()
import argparse
import json
import os
import re
from pathlib import Path
import signal
import time
import uuid
import redis
from redis_recovery_evidence import write, recover
from shared_models.assurance import REDIS_ROLES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "finish"])
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    assert os.getenv("CRYPTOSCAN_DISPOSABLE_REDIS_OPT_IN") == "local-synthetic-fault"
    # Fixed socket and RDB names deliberately prevent connection to a deployment.
    client = redis.Redis(unix_socket_path="/home/user/quality-redis.sock", decode_responses=True,
                         socket_timeout=5, socket_connect_timeout=5)
    info = client.info("server")
    assert info["tcp_port"] == 0
    assert client.config_get("dbfilename")["dbfilename"] == "quality-redis-drill.rdb"
    assert client.config_get("dir")["dir"] == "/home/user"
    assert Path(f"/proc/{info['process_id']}/exe").resolve() == Path("/home/user/redis-8.2.4/src/redis-server")
    ledger = args.directory / "acknowledged.json"
    if args.phase == "prepare":
        args.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        root = "cryptoscan:qualification:recovery:" + uuid.uuid4().hex
        value = {"root": root, "roles": {}, "redis_version": info["redis_version"]}
        for role in REDIS_ROLES:
            identifiers = [str(uuid.uuid4()) for _ in range(15)] if role != "health" else []
            value["roles"][role] = identifiers
            for identifier in identifiers[:10]: write(client, role, root + ":" + role, identifier)
        assert client.save()
        for role, identifiers in value["roles"].items():
            for identifier in identifiers[10:]: write(client, role, root + ":" + role, identifier)
        value["fault_at_unix"] = time.time()
        value["fault_monotonic"] = time.monotonic()
        with ledger.open("x") as stream:
            json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
        os.kill(info["process_id"], signal.SIGKILL)
        print("Actual SIGKILL delivered to the fixed private lab Redis; restart the same lab from its RDB before finish.")
        return
    value = json.loads(ledger.read_text())
    root = value["root"]
    assert re.fullmatch(r"cryptoscan:qualification:recovery:[0-9a-f]{32}", root)
    rows = []
    for role, identifiers in value["roles"].items():
        prefix = root + ":" + role
        recovered = recover(client, role, prefix, identifiers)
        lost = [i for i in identifiers if i not in recovered]
        assert len(recovered) == (0 if role == "health" else 10)
        assert len(lost) == (0 if role == "health" else 5)
        row = {"role": role, "acknowledged": len(identifiers), "recovered_from_rdb": len(recovered),
               "lost_from_rdb": len(lost), "loss_metric_applicable": role != "health"}
        if role in {"queue", "realtime"}:
            for identifier in lost: write(client, role, prefix, identifier)
            assert set(recover(client, role, prefix, identifiers)) == set(identifiers)
            row["reconciliation"] = "Replay missing synthetic IDs from the external fsynced acknowledgement witness; not SQL collector authority"
            if role == "queue":
                client.rpush(prefix + ":queue", identifiers[0])  # duplicate delivery hint
                row["backlog_before_drain"] = client.llen(prefix + ":queue")
                seen, duplicates, samples = set(), 0, []
                while True:
                    start = time.perf_counter(); item = client.lpop(prefix + ":queue")
                    samples.append((time.perf_counter() - start) * 1000)
                    if item is None: break
                    if item in seen: duplicates += 1
                    seen.add(item)
                assert seen == set(identifiers) and duplicates == 1
                row.update(backlog_after_drain=client.llen(prefix + ":queue"), duplicate_hints=duplicates,
                           drain_operations=len(samples), drain_max_ms=max(samples), drain_total_ms=sum(samples))
        elif role == "sso_state":
            for identifier in identifiers: client.delete(prefix + ":" + identifier)
            assert not recover(client, role, prefix, identifiers)
            row["reconciliation"] = "Invalidate all restored scratch session-cache entries; require SQL/current-auth revalidation (separate PG test)"
        elif role == "rate_limit":
            for identifier in identifiers: client.set(prefix + ":" + identifier, str(2**63 - 1), ex=60)
            row["reconciliation"] = "Saturate scratch counters with 60-second recovery hold; consumer fail-closed behavior still unqualified"
        elif role == "health":
            assert client.ping()
            row["reconciliation"] = "PING proves liveness only, never event durability"
        else:
            for identifier in identifiers: client.set(prefix + ":" + identifier, "UNKNOWN_RECOVERY", ex=60)
            row["reconciliation"] = "Replace restored scratch state with UNKNOWN_RECOVERY pending authoritative reconstruction; never restore a green result"
        rows.append(row)
    result = {"scenario": "actual SIGKILL after SAVE plus acknowledged uncheckpointed writes; same private Redis restarted from RDB",
        "redis_version": info["redis_version"], "fault_to_verified_finish_seconds": time.monotonic() - value["fault_monotonic"],
        "roles": rows, "acknowledged_total": sum(r["acknowledged"] for r in rows),
        "lost_from_rdb_total": sum(r["lost_from_rdb"] for r in rows), "independent_review": "PENDING", "deployment_qualification": False,
        "limits": ["Unix socket, standalone RDB, no TLS/ACL/Sentinel/replica/power-loss qualification",
                   "Role-specific scratch structures; not all eight production consumers executed",
                   "Witness-replayed queue/stream IDs do not prove collector effects or exactly-once execution",
                   "Single observer survives the fault; ACK-to-witness crash gap and clock qualification unmeasured",
                   "Recovery duration includes operator restart delay; not a service RTO",
                   "Memory-overcommit warning observed; memory pressure and sustained load not qualified"]}
    (args.directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for key in client.scan_iter(root + "*"): client.delete(key)
    client.close()
    print("Retained actual loss and reconciliation results; scratch keys cleaned; independent review remains pending.")


if __name__ == "__main__": main()

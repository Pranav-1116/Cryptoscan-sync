"""Exact passive kernel process/cgroup evidence; no daemon/socket or discovery."""

import hashlib
import re
from shared_models.oci_content import OciRuntimeFact, runtime_resource, selected_bytes, seal


def membership(raw, runtime, container):
    text = raw.decode("utf-8")
    lines = text.splitlines()
    if not 1 <= len(lines) <= 64:
        raise ValueError("Bounded cgroup table required")
    identities = set()
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[2].startswith("/"):
            raise ValueError("Invalid kernel cgroup framing")
        if any(ord(c) < 32 or ord(c) == 127 for c in line) or any(p == ".." for p in fields[2].split("/")):
            raise ValueError("Invalid kernel cgroup path")
        for engine, ident in re.findall(r"(?:^|/)(docker|cri-containerd)-([0-9a-f]{64})\.scope(?=/|$)", fields[2]):
            identities.add(("containerd" if engine == "cri-containerd" else engine, ident))
        for ident in re.findall(r"(?:^|/)docker/([0-9a-f]{64})(?=/|$)", fields[2]):
            identities.add(("docker", ident))
    if identities != {(runtime, container)}:
        raise ValueError("Exact unambiguous approved container cgroup membership required")


def collect_runtime(item, limit, charge):
    from inventory.linux_runtime import Reader, process, process_start, boot_id, ProbeError

    runtime, container, pid, start, boot, image = runtime_resource(item.path)
    reader = Reader(limit, charge)
    try:
        before = reader.read(f"/proc/{pid}/cgroup")
        first = process(reader, str(pid), False)[0]
        middle = reader.read(f"/proc/{pid}/cgroup")
        second = process(reader, str(pid), False)[0]
        after = reader.read(f"/proc/{pid}/cgroup")
        stat = reader.read(f"/proc/{pid}/stat")
        actual_start = process_start(stat, pid)
        state = stat.decode().rsplit(")", 1)[-1].split()[0]
        if (
            first != second
            or before != middle
            or middle != after
            or state in {"Z", "X", "x"}
            or actual_start != start
            or boot_id(reader) != boot
            or (first.pid, first.process_start_ticks, first.boot_id) != (pid, start, boot)
        ):
            raise ValueError("Changed/reused/exited or out-of-scope process")
        membership(after, runtime, container)
        fact = seal(
            OciRuntimeFact,
            runtime=runtime,
            container_id=container,
            image_manifest_sha256=image,
            process=first,
            identity_key=f"container:{runtime}:{container}:{first.identity_key}",
            source_sha256=reader.digest.hexdigest(),
            cgroup_sha256=hashlib.sha256(after).hexdigest(),
        )
        data = selected_bytes(fact)
        reader.add(data)
        return data, [fact]
    except ProbeError as exc:
        from inventory.host import Refused

        raise Refused(exc.status, exc.reason) from None

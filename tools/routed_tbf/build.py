"""Reuse the locked v1 builder in a private module instance; never mutate v1 files."""

import importlib.util
import json
from pathlib import Path
from tools.disposable_tbf.build import sha

HERE = Path(__file__).resolve().parent
V1 = HERE.parent / "disposable_tbf"
SOURCES = (
    "build.py",
    "guest.py",
    "probe.c",
    "sandbox.c",
    "kernel.config",
    "assets.lock.json",
    "acceptance.json",
    "authority.py",
    "runner.py",
    "report.py",
    "trust.py",
)


def implementation():
    spec = importlib.util.spec_from_file_location("_routed_private_builder", V1 / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE = HERE
    return module


def seal(output):
    p = output / "bundle.json"
    obj = json.loads(p.read_text())
    obj["profile"] = "DISKLESS_TCG_ROUTED_NETNS_V1"
    obj["routed_sources"] = {name: sha(HERE / name) for name in SOURCES}
    obj["reused_builder_sha256"] = sha(V1 / "build.py")
    p.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n")
    return sha(p)


def assemble(output, kernel, config, qemu_root, loader):
    for required in (
        "CONFIG_NET_NS=y",
        "CONFIG_VETH=y",
        "CONFIG_IP_MULTIPLE_TABLES=y",
        "CONFIG_IP_ROUTE_MULTIPATH=y",
        "CONFIG_NET_ACT_GACT=y",
    ):
        if required not in config.read_text().splitlines():
            raise ValueError("missing routed kernel capability: " + required)
    implementation().assemble(output, kernel, config, qemu_root, loader)
    return seal(output)


def build(cache, work, output):
    implementation().build(cache, work, output)
    return seal(output)

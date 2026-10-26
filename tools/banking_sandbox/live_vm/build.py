"""Private reuse of existing diskless builder, adding trusted SSL stdlib/runtime only."""

import importlib.util
import json
from pathlib import Path
import shutil
from tools.disposable_tbf.build import sha

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PRODUCTION = [
    ROOT / "services/network_scanner/network_scanner/probing/tls_handshaker.py",
    ROOT / "services/network_scanner/network_scanner/certificates/cert_parser.py",
]


def assemble(output, kernel, config, qemu_root, loader):
    spec = importlib.util.spec_from_file_location("_bank_private_builder", ROOT / "tools/disposable_tbf/build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HERE = HERE
    original = module.initramfs

    def pack(root, dest):
        module.copy_elf("/usr/bin/openssl", "/bin/openssl", root)
        for source in Path("/usr/lib/python3.11/lib-dynload").glob("*.so"):
            module.copy_elf(source, str(source), root)
        for source in PRODUCTION:
            target = root / "network_scanner" / source.parent.name / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            (target.parent / "__init__.py").touch()
        (root / "network_scanner/__init__.py").touch()
        original(root, dest)

    module.initramfs = pack
    module.assemble(output, kernel, config, qemu_root, loader)
    p = output / "bundle.json"
    v = json.loads(p.read_text())
    v["profile"] = "SYNTHETIC_BANK_LIVE_NO_NIC_V1"
    v["production_collector_sources"] = {str(p.relative_to(ROOT)): sha(p) for p in PRODUCTION}
    p.write_text(json.dumps(v, sort_keys=True, indent=2) + "\n")
    return sha(p)

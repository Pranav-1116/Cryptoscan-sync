"""Portable positive parser fixtures ONLY: not native DMI/TPM execution evidence."""

import sys
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(root / "scripts"))
from _bootstrap import bootstrap

bootstrap()
from inventory.linux_runtime import Reader, hardware
from shared_models.host_runtime import RuntimeFact


class SyntheticReader(Reader):
    def read(self, path, magic=0x9FA0):
        assert magic == 0x62656572
        fields = {
            "/sys/devices/virtual/dmi/id/sys_vendor": b"Fixture Manufacturer\n",
            "/sys/devices/virtual/dmi/id/product_name": b"Fixture Model\n",
            "/sys/devices/virtual/dmi/id/bios_version": b"1.2-fixture\n",
            "/sys/devices/fixture/tpm0/tpm_version_major": b"2\n",
        }
        return self.add(fields[path])


reader = SyntheticReader(1048576, lambda count: None)
data, facts = reader.finish(hardware(reader, "dmi"))
assert len(facts) == 1 and facts[0].model == "Fixture Model"
assert facts[0].tpm_major_version is None and facts[0].interface_sha256
RuntimeFact.model_validate(facts[0].model_dump(mode="json"))
reader = SyntheticReader(1048576, lambda count: None)
with (
    patch("inventory.linux_runtime.os.lstat"),
    patch("inventory.linux_runtime.os.path.realpath", return_value="/sys/devices/fixture/tpm0"),
):
    data, facts = reader.finish(hardware(reader, "tpm0"))
assert facts[0].tpm_major_version == 2 and facts[0].operation_use == "UNKNOWN"
assert not facts[0].capabilities_observed
RuntimeFact.model_validate(facts[0].model_dump(mode="json"))
print("PASS: synthetic DMI/TPM positive parser fixtures; native execution NOT qualified")

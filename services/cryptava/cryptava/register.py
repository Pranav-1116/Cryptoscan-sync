"""The asset register record — what the bank's CMDB / procurement system knows about
this host that the host itself cannot know.

Two planes need it:

* **HBOM** — when the platform exposes no firmware tables (containers, many VMs, WSL),
  the machine's identity (manufacturer, model, serial, asset tag, rack location,
  warranty) has to come from the asset register;
* **VBOM** — contracts, support entitlements and account managers are commercial facts
  and are never on a host.

The record is a small JSON file the bank's deployment tooling drops next to the agent
config (default ``/etc/cryptava/asset-record.json``; the Ansible role and ``install.sh
--asset-record`` both write it). It is read from the agent's own filesystem, like the
config, never from the scanned root. Everything taken from it is sent as ``IMPORTED``
evidence with the record's ``source`` named, so the platform never confuses a register
entry with something the agent observed.

.. code-block:: json

    {
      "source": "Meridian CMDB export",
      "exported_at": "2026-11-01",
      "hardware": {"manufacturer": "Dell Technologies", "model": "PowerEdge R750",
                   "serial_number": "7Q2K3X3", "asset_tag": "MRDN-DC1-000412",
                   "location": "DC1 / Hall B / Rack 04 / U12", "warranty_end": "2028-04-30"},
      "contracts": [
        {"vendor": "Dell Technologies", "contract_id": "PSP-88213", "support_level": "ProSupport Plus 4h",
         "start": "2023-05-01", "end": "2028-04-30", "account_manager": "R. Iyer"},
        {"vendor": "Alpine Linux", "support_level": "community", "note": "no commercial support"}
      ]
    }

``covers`` names component vendors an OEM contract also covers (a server support contract
covers the Intel CPU and Broadcom NIC inside it); ``products`` narrows an entry to some of
the vendor's products. ``support_level`` ``community`` / ``internal`` mark a supplier the
bank deliberately has no commercial contract with (open-source, its own PKI).

.. code-block:: json

    {"contracts": [{"vendor": "Dell Technologies", "covers": ["Intel", "Broadcom"], "end": "2028-04-30"}]}

Inline ``hardware`` / ``contracts`` keys in the agent config (or ``CRYPTAVA_HARDWARE`` /
``CRYPTAVA_CONTRACTS`` as JSON) override the file's sections.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

DEFAULT_RECORD_PATH = "/etc/cryptava/asset-record.json"

HARDWARE_FIELDS = (
    "manufacturer", "model", "serial_number", "asset_tag", "platform", "location", "rack",
    "cluster", "purchase_date", "warranty_end", "end_of_life", "owner", "cpu", "memory_gb",
)
CONTRACT_FIELDS = (
    "vendor", "products", "covers", "contract_id", "support_level", "entitlement", "start", "end",
    "renewal", "account_manager", "support_contact", "note",
)
#: support levels that mean "nobody is paid to fix this" — still a register entry, not a gap
COMMUNITY_LEVELS = {"community", "none", "self-supported", "no commercial support"}
#: the bank's own suppliers-of-record (its private CA, in-house builds)
INTERNAL_LEVELS = {"internal", "in-house", "inhouse", "owned"}


class Register:
    """The loaded record plus what happened while loading it (for the plane's sources)."""

    def __init__(self, data: dict[str, Any], path: str | None, state: str, note: str | None = None) -> None:
        self.data = data
        self.path = path
        self.state = state          # READ | ABSENT | NOT_CONFIGURED | UNAVAILABLE
        self.note = note

    @property
    def label(self) -> str:
        return str(self.data.get("source") or (f"asset register {self.path}" if self.path else "asset register"))

    @property
    def exported_at(self) -> str | None:
        value = self.data.get("exported_at")
        return str(value) if value else None

    @property
    def hardware(self) -> dict[str, Any]:
        raw = self.data.get("hardware")
        if not isinstance(raw, dict):
            return {}
        return {key: raw[key] for key in HARDWARE_FIELDS if raw.get(key) not in (None, "", [], {})}

    @property
    def contracts(self) -> list[dict[str, Any]]:
        raw = self.data.get("contracts")
        if not isinstance(raw, list):
            return []
        out = []
        for item in raw:
            if isinstance(item, dict) and str(item.get("vendor") or "").strip():
                out.append({key: item[key] for key in CONTRACT_FIELDS if item.get(key) not in (None, "", [], {})})
        return out

    @property
    def has_contract_register(self) -> bool:
        return isinstance(self.data.get("contracts"), list)

    def hardware_identified(self) -> bool:
        hw = self.hardware
        return bool((hw.get("manufacturer") or hw.get("model")) and (hw.get("serial_number") or hw.get("asset_tag")))


def load(config: dict[str, Any]) -> Register:
    explicit = config.get("asset_record")
    path = str(explicit) if explicit else DEFAULT_RECORD_PATH
    data: dict[str, Any] = {}
    state, note = "NOT_CONFIGURED", None
    file = Path(path)
    if file.is_file():
        try:
            loaded = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            state, note = "UNAVAILABLE", f"{path}: {exc}"[:200]
        else:
            if isinstance(loaded, dict):
                data, state = loaded, "READ"
            else:
                state, note = "UNAVAILABLE", f"{path}: the record must be a JSON object"
    elif explicit:
        state, note = "ABSENT", f"{path} not found"
    for key in ("hardware", "contracts"):
        inline = config.get(key)
        if inline:
            data[key] = inline
            if state != "READ":
                state = "READ"
                data.setdefault("source", "agent configuration")
    return Register(data, path if (state != "NOT_CONFIGURED" or explicit) else None, state, note)


def get(ctx: Any) -> Register:
    """Load once per collection cycle and keep it on the context."""
    cached = getattr(ctx, "register", None)
    if cached is None:
        cached = load(ctx.config)
        ctx.register = cached
    return cached


def date_state(value: Any, *, active: str, lapsed: str) -> str | None:
    """``active`` if the ISO date is today or later, ``lapsed`` if it has passed, None if unparseable."""
    try:
        when = date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
    return active if when >= date.today() else lapsed

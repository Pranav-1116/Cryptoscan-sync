"""Drift service core engine and orchestration.

Modules:
- comparator: Comparator — compares baseline and current crypto inventories
- detector: Drift detector — fingerprint comparison plus the inventory/comparator API
- gate: Purpose-aware CI / PR drift gate
"""

"""Certificate inventory plus the structured network inventory contract."""

# Keep the certificate inventory package stable while exposing the structured
# network inventory from its non-conflicting submodule.
from network_scanner.inventory.network_inventory import (  # noqa: F401
    NetworkInventoryDocument,
    configuration_drift,
    topology_graph,
    inventory_approval_issues,
    inventory_completeness,
    inventory_hash,
    inventory_risk,
    parse_inventory,
)

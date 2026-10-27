"""Built-in ZELNX connectors (contributed implementations).

Importing this package registers the built-in connectors into the SDK registry
so the platform can discover/resolve them without hard-coded dispatchers.
"""

from __future__ import annotations

from connector_sdk.contrib.terraform_connector import TerraformIaCConnector

# ensure they are registered on import (side-effect via @register_connector)
__all__ = ["TerraformIaCConnector"]

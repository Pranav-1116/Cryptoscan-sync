"""Per-vendor and vendor-neutral HSM readers (phase H4).

The HSM scanner describes an appliance from whatever a caller hands it. These
readers produce that input from the appliance itself, over surfaces a bank's
HSM estate actually exposes:

* :mod:`.pkcs11` — token/partition metadata and the mechanism list through
  ``pkcs11-tool``, with the PIN kept out of argv and no object ever fetched;
* :mod:`.kmip_query` — the KMIP ``Query`` operation: vendor identification,
  supported operations, object types and profiles, with no key identifier in
  the message;
* :mod:`.rest` — the appliance's own HTTPS API, read only through endpoints a
  published vendor document names (a manifest per vendor, and a refusal for the
  vendors whose documentation has not been read).

Both return a ``to_raw()`` dict in the shape
:class:`~universal_vendor.hardware.hsm_hw.HsmHardwareScanner` already reads, so
there is one HSM observation shape in the tree and not one per protocol.
"""

from __future__ import annotations

from universal_vendor.hardware.hsm_readers.kmip_query import (
    FunctionNotAllowed,
    KmipCapabilities,
    KmipQueryError,
    KmipQueryReader,
    algorithm_name,
    parse_query_response,
    query_request,
    tls_transport,
)
from universal_vendor.hardware.hsm_readers.rest import (
    THALES_LUNA,
    UNDOCUMENTED as UNDOCUMENTED_HsmVendors,
    VENDORS as HSM_REST_VENDORS,
    DocumentedEndpoint,
    EndpointNotAllowed,
    HsmRestFacts,
    RestHsmReader,
    RestReadError,
    VendorManifest,
    VendorNotDocumented,
    build_url,
    https_json_transport,
    manifest_for,
)
from universal_vendor.hardware.hsm_readers.pkcs11 import (
    PQC_FAMILIES,
    CommandNotAllowed,
    CommandResult,
    HsmReadResult,
    PinOnCommandLineRefused,
    Pkcs11Reader,
    build_argv,
    mechanism_families,
    parse_mechanisms,
    parse_token_info,
    pqc_families,
    validate_module_path,
)

__all__ = [
    "PQC_FAMILIES",
    "DocumentedEndpoint",
    "EndpointNotAllowed",
    "HSM_REST_VENDORS",
    "HsmRestFacts",
    "RestHsmReader",
    "RestReadError",
    "THALES_LUNA",
    "UNDOCUMENTED_HsmVendors",
    "VendorManifest",
    "VendorNotDocumented",
    "build_url",
    "https_json_transport",
    "manifest_for",
    "CommandNotAllowed",
    "CommandResult",
    "FunctionNotAllowed",
    "HsmReadResult",
    "KmipCapabilities",
    "KmipQueryError",
    "KmipQueryReader",
    "PinOnCommandLineRefused",
    "Pkcs11Reader",
    "algorithm_name",
    "build_argv",
    "mechanism_families",
    "parse_mechanisms",
    "parse_query_response",
    "parse_token_info",
    "pqc_families",
    "query_request",
    "tls_transport",
    "validate_module_path",
]

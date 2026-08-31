"""connector_plugin.py — the assembled plugin class.

Combines the connector (detection/validation) with the discovery and
normalizer mixins. This class carries ``plugin_id`` matching the manifest,
so the SDK loader picks it up automatically.
"""

from __future__ import annotations

from .connector import MyVendorPluginConnector
from .discovery import DiscoveryMixin
from .normalizer import NormalizerMixin


class MyVendorPlugin(DiscoveryMixin, NormalizerMixin, MyVendorPluginConnector):
    """Assembled plugin: mixins first so their concrete methods shadow the
    abstract ones inherited through the connector (MRO order matters)."""

    plugin_id = "my_vendor_product"
    vendor = "MyVendor"
    product = "MyProduct"

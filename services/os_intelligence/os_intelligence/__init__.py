"""OS & Kernel Intelligence Engine (docs/os-kernel-intelligence/
01_PRODUCT_SPEC.md).

Read-only collection, Tier 1 by default (§11): the engine reads
supported OS interfaces and normalizes evidence; it never modifies
kernel state, never installs modules, never executes uploaded
artifacts, and never extracts key material. Unavailable information is
RECORDED as unavailable — never treated as disabled (§2.1).
"""

"""External-tool adapters (docs/binary-intelligence/01_PRODUCT_SPEC.md
§10). These modules invoke third-party ANALYSIS TOOLS under declared
bounds. They never execute the analyzed artifact, and third-party
output is always a LEAD to validate and normalize — never authoritative
evidence. The core engine (../binary_intelligence/) contains no
execution primitives; tool invocation lives only here.
"""

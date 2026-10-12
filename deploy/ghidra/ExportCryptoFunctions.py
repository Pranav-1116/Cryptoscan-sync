# Ghidra headless post-script: export functions with crypto constants
# (advanced/52, round 38). Run by universal_crypto.binary_cfa via
#   analyzeHeadless <projdir> CryptoScanCFA -import <bin> \
#     -scriptPath deploy/ghidra -postScript ExportCryptoFunctions.py
#
# For every function the script reads its body bytes and searches for the
# leading bytes of well-known crypto tables (AES S-box / inverse S-box /
# T-table, DES initial permutation). Matches are attributed to the
# function. Output contract: the LAST stdout line is one JSON object
#   {"functions": [{"name", "address", "size", "algorithms", "hits"}]}
#
# External half: this script needs a real Ghidra installation to execute
# (Jython 2.7 inside Ghidra); the Python side parses its output.
# @category CryptoScan
# @runtime Jython
# ruff: noqa: F821 — currentProgram/monitor/getByte are Ghidra script globals

import json

from ghidra.program.model.block import BasicBlockModel

SBOX_HEAD = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])
INV_SBOX_HEAD = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb])
# T0[0] = 0xc66363a5 (big-endian byte order in tables)
T0_HEAD = bytes([0xc6, 0x63, 0x63, 0xa5])
T0_HEAD_LE = bytes([0xa5, 0x63, 0x63, 0xc6])
DES_IP_HEAD = bytes([0x0e, 0x04, 0x0d, 0x01])

PATTERNS = [
    ("AES", SBOX_HEAD),
    ("AES", INV_SBOX_HEAD),
    ("AES-T-table", T0_HEAD),
    ("AES-T-table", T0_HEAD_LE),
    ("DES", DES_IP_HEAD),
]


def function_body(func):
    body = bytearray()
    blocks = BasicBlockModel(currentProgram).getCodeBlocksContaining(
        func.getBody(), monitor)
    for block in blocks:
        addr = block.getMinAddress()
        end = block.getMaxAddress()
        while addr is not None and addr.compareTo(end) <= 0:
            body.append(getByte(addr) & 0xFF)
            addr = addr.add(1)
    return bytes(body)


def attribute(body):
    algorithms = []
    hits = 0
    for algorithm, pattern in PATTERNS:
        if pattern in body:
            hits += body.count(pattern)
            if algorithm not in algorithms:
                algorithms.append(algorithm)
    return algorithms, hits


functions = []
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    size = func.getBody().getNumAddresses()
    if size <= 0:
        continue
    try:
        algorithms, hits = attribute(function_body(func))
    except Exception:
        algorithms, hits = [], 0
    functions.append({
        "name": func.getName(),
        "address": "0x%x" % func.getEntryPoint().getOffset(),
        "size": size,
        "algorithms": algorithms,
        "hits": hits,
    })

functions.sort(key=lambda f: (-f["hits"], f["address"]))
print(json.dumps({"functions": functions}))

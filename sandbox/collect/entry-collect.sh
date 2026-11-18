#!/bin/sh
# sandbox-collect entrypoint: install the two libs the collector needs
# (docker SDK for the daemon socket, psycopg for the ledger version probe),
# then run one collection pass.
set -e
pip install -q docker 'psycopg[binary]'
exec python /collect/collect_estate.py

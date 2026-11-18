#!/bin/sh
# core-banking-db boot wrapper: hand PostgreSQL a private copy of the shared
# sandbox certs with the ownership/mode it demands (postgres:postgres 0600),
# then start the real server with SSL on so the estate's 5432 endpoint
# answers STARTTLS exactly like a bank's hardened database would.
set -e
mkdir -p /pgsql-certs
cp /certs/core-db.crt /certs/core-db.key /pgsql-certs/
chown postgres:postgres /pgsql-certs/core-db.crt /pgsql-certs/core-db.key
chmod 0600 /pgsql-certs/core-db.key
chmod 0644 /pgsql-certs/core-db.crt
exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/pgsql-certs/core-db.crt \
  -c ssl_key_file=/pgsql-certs/core-db.key

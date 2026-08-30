-- Runs once on the PRIMARY's first boot: replication user + minimal privileges.
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD :'REPL_PASSWORD';

# systemd units — scheduled production backups

Install on the production host (repo checkout assumed at `/opt/cryptoscan`):

```bash
sudo cp deploy/systemd/cryptoscan-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptoscan-backup.timer
systemctl list-timers cryptoscan-backup.*
```

- The service runs `scripts/db_backup.sh` (postgres custom-format dump +
  sha256 manifest + retention; add `--with-neo4j` inside the unit if you also
  want the graph dump).
- **Uncomment the `ExecStartPost` line** in the service unit to copy
  `backups/db/` off the host — a backup that lives on the same disk is not a
  backup.
- Restore: `scripts/db_restore.sh backups/db/pg-<ts>.dump` (checksum-first,
  asks for confirmation) — see `docs/runbooks/dr-recovery.md`.

Verify a restore at least quarterly as part of the failover drill
(`docs/runbooks/dr-recovery.md` §5).

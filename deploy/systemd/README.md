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

## Integrity + recovery schedules (the other half of backup automation)

```bash
sudo cp deploy/systemd/cryptoscan-audit-verify.{service,timer} /etc/systemd/system/
sudo cp deploy/systemd/cryptoscan-restore-drill.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptoscan-audit-verify.timer cryptoscan-restore-drill.timer
systemctl list-timers 'cryptoscan-*'
```

- **`cryptoscan-audit-verify.timer`** (daily) runs `scripts/audit_verify.py`:
  the audit hash chain must verify. Exit `1` = **TAMPERED** (incident),
  exit `2` = could not verify — either way the unit FAILS and your
  unit-failure alerting lights up. Discovery by happenstance is not an
  integrity program.
- **`cryptoscan-restore-drill.timer`** (weekly) runs
  `scripts/backup_drill.py --record-evidence`: restores the latest backup
  into a scratch instance and records the verdict in the signed
  production-evidence chain. The only backup that counts is one that has
  restored.
- **`cryptoscan-evidence-checkpoint.timer`** (weekly, Monday 04:15) runs
  `scripts/evidence_checkpoint_timer.sh`: verifies last week's signed
  evidence-chain checkpoint, proves the live chain still CONTAINS what it
  anchored (`continuity`), then signs this week's checkpoint and promotes
  it only after it verifies. Requires `EVIDENCE_CHECKPOINT_KEY` in
  `/etc/cryptoscan/evidence-checkpoint.env` (no default key exists — the
  unit fails without it, on purpose). Archive the checkpoint files per
  `docs/runbooks/evidence-checkpoint-archive.md`.

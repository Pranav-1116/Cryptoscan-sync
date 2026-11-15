# CryptoScan Ansible (IaC row: "Use Ansible/Terraform where suitable")

Repeatable installation and upgrades for the single-server Docker Compose
form of CryptoScan. The Kubernetes form is `k8s/` + `k8s/helm/cryptoscan/`.

```bash
cd deploy/ansible
ansible-playbook -i inventory.example.ini site.yml
```

What the playbook guarantees:

* **Never reaches the internet.** Runtime packages come from the bank's
  internal mirror; images from the internal registry; the release from
  `make offline-bundle` output.
* **Refuses unverified releases** — no signed manifest at
  `/opt/cryptoscan/release/manifest.sig`, no install.
* **Secrets are files, not values** — `*_FILE` references into the
  root-only `secrets/` directory; the secrets manager resolves them.
* **Backup automation installed** — the systemd timer the repo ships is
  enabled as part of installation, not after the first incident.

Roles: `common` (users/limits), `runtime` (container engine),
`cryptoscan` (stack), `backup` (timer). Prose contract:
`docs/admin-guide/infrastructure.md` (IaC row).

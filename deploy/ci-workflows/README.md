# GitHub Actions workflows (staged copies)

The sandbox's GitHub App token cannot push to `.github/workflows/` (missing
`workflows` permission), so the four production workflows ship here and are
maintained locally in `.github/workflows/`.

To activate on GitHub (one command from a checkout with permission):

    cp deploy/ci-workflows/*.yml .github/workflows/
    git add .github/workflows && git commit -m "ci: activate production workflows" && git push

Workflows: `ci.yml` (lint + backend matrix + frontend + prod-config guard),
`scanner-tests.yml` (offline scanner suites, nightly), `db-migration.yml`
(alembic on PostgreSQL 15), `docker-build.yml` (all six images).

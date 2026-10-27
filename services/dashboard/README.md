# CryptoScan dashboard

This directory holds the **legacy air-gap shell**: a self-contained
`index.html` (vanilla JS, no build step, no external CDN dependencies). It is
*not* the operator console.

The operator console is `frontend/` — TypeScript + React + Vite, 75 page
components / 80 lazy-loaded routes, its own 334-test Vitest suite and a clean
`tsc --noEmit` (`make test-frontend`). Compose builds it from
`.docker/frontend/Dockerfile` and serves it on `${FRONTEND_PORT:-3003}` behind
nginx (`:8088`), which proxies `/api` + `/health` to the API with SSE-safe
settings. In local development it runs from `frontend` with Vite proxying
`/api` to `:8010`.

How this shell is still reached: `api/main.py` answers `/` with
`services/dashboard/dist/index.html` when a console build has been copied
there, and otherwise falls back to this `index.html`. Nothing in the tree
currently produces `dist/` here, so in practice the API's `/` route serves this
legacy shell while the real console is served by nginx/Vite.

(The earlier claim in this file that "there is no React/Vite build" was true in
August 2026 — the empty `src/` scaffolding it refers to was replaced by the
`frontend/` app, which is built, tested and typechecked in CI. Corrected
2026-10-16, round 80.)

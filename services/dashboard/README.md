# CryptoScan dashboard

The production UI is the self-contained `index.html` (vanilla JS SPA, no
build step, no external CDN dependencies — air-gap friendly). Nginx (`.docker/dashboard/`)
or the API's `/` fallback serves it.

There is no React/Vite build: the previous empty `src/` scaffolding was removed.
If a framework migration happens, replace this file's contents entirely and add
`src/tests` coverage for every view (login, scans, findings, drift, job status).

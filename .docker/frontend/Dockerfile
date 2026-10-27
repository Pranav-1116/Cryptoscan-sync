# ZELNX console — the realtime frontend (React + Vite build → nginx).
#
# Port (browser-facing): 3003 — published as ${FRONTEND_PORT:-3003} in compose.
# The nginx server block proxies /api + /health to the backend (service "api",
# :8010) with SSE-safe settings (buffering off, long read timeout) so the
# realtime event stream works through the container boundary.

# ── build stage ──────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app

# The checked-in lock and engine policy are mandatory. A build must not silently
# resolve a different dependency graph or tolerate an unsupported Node runtime.
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci --no-audit --no-fund

# Build the static bundle.
COPY frontend/ ./
RUN npm run build

# ── runtime stage ────────────────────────────────────────────────────
FROM nginx:1.29-alpine AS runtime

COPY .docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# nginx runs as the unprivileged built-in user; make the cache + content
# writable/readable accordingly and drop root from the runtime.
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/run \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 3003

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=8 \
    CMD wget -q -O /dev/null http://127.0.0.1:3003/ || exit 1

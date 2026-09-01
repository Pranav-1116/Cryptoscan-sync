# ZELNX console — the realtime frontend (React + Vite build → nginx).
#
# Ports (matching the host-side contract):
#   frontend :3003  (browser-facing, proxied via compose to ${FRONTEND_PORT:-3003})
#   api      :8010   (upstream backend — internal network only)
#
# The nginx server block proxies /api to the backend with SSE-safe settings
# (buffering off, long read timeout) so the realtime event stream works
# through the container boundary.

FROM node:20-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY .docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 3003

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=8 \
    CMD wget -qO- http://127.0.0.1:3003/ >/dev/null 2>&1 || exit 1

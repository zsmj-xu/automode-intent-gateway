# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build the React console (web/dist) with Node
# ---------------------------------------------------------------------------
FROM node:20-alpine AS web-builder

WORKDIR /src/web

# Leverage layer cache: install dependencies before copying sources.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ .
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: Python runtime serving the gateway + static console
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# pyproject.toml (hatchling) requires README.md to build the package.
COPY pyproject.toml README.md ./
COPY automode_gateway/ ./automode_gateway/
RUN pip install --no-cache-dir .

# Serve the pre-built console from the gateway itself (GET /).
# Wheel installs put the package under site-packages, so __file__-relative
# resolution cannot find web/dist; point the frontend at an explicit path.
COPY --from=web-builder /src/web/dist ./web/dist
ENV AUTOMODE_WEB_DIST=/app/web/dist

# SQLite data directory (persisted as a volume, see docker-compose.yml).
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health', timeout=3)" || exit 1

# Non-loopback binding requires AUTOMODE_ADMIN_TOKEN (set via compose/.env).
CMD ["auto-intent", "serve", "--host", "0.0.0.0", "--port", "8787", "--db", "/app/data/automode.db"]

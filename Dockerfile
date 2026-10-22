# php2shell C2 console - build stage
# syntax=docker/dockerfile:1
FROM oven/bun:1.2 AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

FROM oven/bun:1.2 AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# next.config.ts uses output:"standalone"; package.json build copies static assets in
RUN bun run build

# runtime: bun + python3 (the exploit engine) on a slim debian base
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=oven/bun:1.2 /usr/local/bin/bun /usr/local/bin/bun

WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    ENGINE_DIR=/app/engine \
    P2S_AGENT_PORT=47017 \
    PYTHON_BIN=python3

COPY --from=build /app/.next/standalone ./
COPY --from=build /app/engine ./engine

EXPOSE 3000
CMD ["bun", "server.js"]

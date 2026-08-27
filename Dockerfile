# syntax=docker/dockerfile:1

# ── Stage 1: build the management UI (Vite/React SPA) ──────────────────────────
# The UI depends on the TS client lib via `file:../typescript`, so build the lib first.
FROM node:24-slim AS ui
WORKDIR /build
COPY clients/typescript ./clients/typescript
RUN cd clients/typescript && npm ci && npm run build
COPY clients/ui ./clients/ui
RUN cd clients/ui && npm ci && npm run build

# ── Stage 2: build the Rust binary (release) ───────────────────────────────────
FROM rust:1.98 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Brand SVGs embedded into the binary via include_str! (src/web_ui.rs).
COPY ci ./ci
RUN cargo build --release --features open_telemetry

# ── Stage 3: runtime ───────────────────────────────────────────────────────────
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/umami /app/umami
# Bake the built SPA in; umami serves it under /app when UMAMI_UI_DIR points at it.
COPY --from=ui /build/clients/ui/dist /app/ui

ARG APP_VERSION="DEVELOPMENT-SNAPSHOT"
ENV APP_NAME=umami \
    APP_VERSION=$APP_VERSION \
    BIND_ADDRESS=0.0.0.0:8080 \
    RUST_LOG=info \
    UMAMI_UI_DIR=/app/ui

EXPOSE 8080/tcp
ENTRYPOINT ["/app/umami"]

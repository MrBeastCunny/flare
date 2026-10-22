# syntax=docker/dockerfile:1.7
#
# Production image for Flare: builds the web UI, embeds it into a static Go
# binary and ships it on a distroless, non-root base image.
#
#   docker build -t flare:latest --build-arg VERSION=1.0.0 .

ARG GO_VERSION=1.27
ARG NODE_VERSION=24

# ---------------------------------------------------------------------------
# 1. Web UI
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS web
ENV CI=true
RUN corepack enable && corepack prepare pnpm@10.31.0 --activate
WORKDIR /src/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY web/ ./
# Vite writes the bundle to ../server/internal/web/dist (embedded by Go).
RUN mkdir -p /src/server/internal/web && pnpm run build

# ---------------------------------------------------------------------------
# 2. API server
# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS api
WORKDIR /src/server
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-buildvcs=false
COPY server/go.mod server/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY server/ ./
RUN rm -rf internal/web/dist
COPY --from=web /src/server/internal/web/dist ./internal/web/dist
ARG VERSION=1.0.0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go test ./... && \
    go build -trimpath \
      -ldflags "-s -w -X github.com/flare-dns/flare/internal/api.Version=${VERSION}" \
      -o /out/flare ./cmd/flare

# ---------------------------------------------------------------------------
# 3. Runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="Flare" \
      org.opencontainers.image.description="Multi-tenant DNS management dashboard for PowerDNS Authoritative" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Proprietary"
COPY --from=api /out/flare /usr/local/bin/flare
ENV FLARE_LISTEN_ADDR=:8080 \
    FLARE_LOG_FORMAT=json
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/flare", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/flare"]
CMD ["serve"]

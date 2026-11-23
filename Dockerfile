FROM golang:1.27-alpine AS builder

RUN apk add --no-cache git build-base ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG MOCC_VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux
# Build with aggressive optimization for size
RUN go build -trimpath -ldflags="-s -w -extldflags '-static' -X main.version=${MOCC_VERSION}" -tags netgo -o /out/mocc ./cmd/mocc
RUN apk add --no-cache upx
# Use UPX brute force mode for maximum compression
RUN upx --best --ultra-brute /out/mocc

# Final stage: minimal image
FROM scratch

# Add CA certs for HTTPS if the app needs them (copied from builder)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the compiled binary
COPY --from=builder /out/mocc /usr/local/bin/mocc

# Copy templates and static files
## templates/static are embedded into the binary via go:embed
# Provide a default users.yaml and allow it to be overridden by a volume mount
COPY --from=builder /src/users.yaml /config/users.yaml
VOLUME ["/config"]

# Environment variables with sensible defaults. Users can override at runtime or via Dockerfile --env
ENV USERS="/config/users.yaml"
ENV HOST=0.0.0.0
ENV PORT=9999
ENV GIN_MODE=release

EXPOSE 9999

ENTRYPOINT ["/usr/local/bin/mocc"]

# Build provenance (populated by CI build-args: GIT_COMMIT/GIT_BRANCH/BUILD_DATE/VERSION).
# Kept last so per-build values don't invalidate the cache of the steps above.
ARG GIT_COMMIT
ARG GIT_BRANCH
ARG BUILD_DATE
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/jonasbg/mocc" \
      org.opencontainers.image.revision="$GIT_COMMIT" \
      org.opencontainers.image.ref.name="$GIT_BRANCH" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.title="mocc" \
      org.opencontainers.image.description="Minimal OpenID Connect (OIDC) mock provider for local development and testing" \
      org.opencontainers.image.vendor="jonasbg" \
      org.opencontainers.image.url="https://github.com/jonasbg/mocc" \
      org.opencontainers.image.documentation="https://github.com/jonasbg/mocc#readme"

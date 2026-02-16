# Multi-stage build for minimal image size (<50MB target)

# Stage 1: Build
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with version info
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=1 go build \
    -ldflags="-s -w \
    -X github.com/dativo-io/talon/internal/cmd.Version=${VERSION} \
    -X github.com/dativo-io/talon/internal/cmd.Commit=${COMMIT} \
    -X github.com/dativo-io/talon/internal/cmd.BuildDate=${BUILD_DATE}" \
    -o talon ./cmd/talon/

# Stage 2: Runtime
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs tzdata && \
    adduser -D -u 1000 talon

# Copy binary
COPY --from=builder /build/talon /usr/local/bin/talon

# Create data directory
RUN mkdir -p /home/talon/.talon && chown -R talon:talon /home/talon

USER talon
WORKDIR /home/talon

EXPOSE 8080

# TODO: Replace with HTTP health check once `talon serve` is implemented (Prompt 6)
# HEALTHCHECK CMD ["wget", "-q", "--spider", "http://localhost:8080/healthz"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD talon version || exit 1

ENTRYPOINT ["talon"]
CMD ["serve"]

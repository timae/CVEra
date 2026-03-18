# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

ARG LDFLAGS="-s -w"

WORKDIR /src

# Cache dependency downloads separately from source code.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree.
COPY . .

# Compile a static binary. CGO_ENABLED=0 ensures portability to distroless.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags "${LDFLAGS}" \
      -trimpath \
      -o /out/cvera \
      ./cmd/cvera

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# gcr.io/distroless/static-debian12 is ~2 MB and contains no shell,
# package manager, or OS user tools — minimising attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

# Copy the compiled binary.
COPY --from=builder /out/cvera /usr/local/bin/cvera

# Copy migrations — the serve command runs them on startup.
COPY --from=builder /src/migrations /migrations

# The nonroot image runs as uid 65532 by default.
# Explicitly declare it for clarity and Kubernetes security contexts.
USER 65532:65532

# Expose the HTTP API port (configurable; default 8080).
EXPOSE 8080

# Default command. Override --config via env CVERA_CONFIG_PATH or a ConfigMap.
ENTRYPOINT ["/usr/local/bin/cvera"]
CMD ["serve"]

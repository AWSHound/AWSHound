# syntax=docker/dockerfile:1
#
# awshound build. Single source of truth for both artifacts the release
# workflow (.github/workflows/release.yml) publishes on push to main:
#
#   * `runtime`  target -> the container image pushed to ghcr.io (entrypoint IS
#                          the awshound binary), built multi-arch via buildx.
#   * `export`   target -> just the raw cross-compiled binary, extracted with
#                          `buildx build --target export --output type=local` for
#                          the standalone release downloads.
#
# The binary is CGO-free, so a single native build stage cross-compiles to any
# GOOS/GOARCH — buildx sets TARGETOS/TARGETARCH from --platform for the image, and
# the binaries job passes them as --build-arg for OSes with no container platform
# (e.g. darwin).

FROM --platform=$BUILDPLATFORM golang:1.24 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
# Download modules first so they cache across source-only changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/awshound ./cmd/awshound

# --- Container image: minimal runtime with CA certs for the AWS SDK's TLS calls.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/awshound /usr/local/bin/awshound
ENTRYPOINT ["/usr/local/bin/awshound"]

# --- Binary export: nothing but the compiled binary, for `--output type=local`.
FROM scratch AS export
COPY --from=build /out/awshound /awshound

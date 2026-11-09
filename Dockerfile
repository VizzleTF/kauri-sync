# Compiles on the build machine for the target platform, so multi-arch
# images build without emulation. Base images are pinned by digest;
# Dependabot keeps them current.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o /kauri-sync ./cmd/kauri-sync

# A static binary on distroless: no shell, no package manager, not root.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /kauri-sync /kauri-sync
EXPOSE 8296
# The image has no curl; the binary checks /readyz itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/kauri-sync", "healthcheck"]
ENTRYPOINT ["/kauri-sync"]

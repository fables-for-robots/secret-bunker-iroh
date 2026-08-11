FROM rust:1.91-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p secret-bunker-operator --bin operator

# distroless/cc: glibc + CA certs, nothing else; :nonroot runs as uid 65532,
# matching the chart's runAsUser/fsGroup.
FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/fables-for-robots/secret-bunker-iroh" \
      org.opencontainers.image.description="secret-bunker → Kubernetes Secret sync operator" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
COPY --from=builder /build/target/release/operator /operator
USER 65532:65532
ENTRYPOINT ["/operator"]

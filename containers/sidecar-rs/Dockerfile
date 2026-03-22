FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=ghostunnel/ghostunnel:v1.9.2 /usr/bin/ghostunnel /usr/bin/ghostunnel
COPY --from=builder /build/target/release/sidecar /usr/bin/sidecar

ENTRYPOINT ["/usr/bin/sidecar"]

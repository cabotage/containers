FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release

FROM alpine:3.23.3

COPY --from=ghostunnel/ghostunnel:v1.9.2 /usr/bin/ghostunnel /usr/bin/ghostunnel
COPY --from=builder /build/target/release/sidecar /usr/bin/sidecar

USER nobody
ENTRYPOINT ["/usr/bin/sidecar"]

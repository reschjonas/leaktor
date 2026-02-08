FROM rust:bookworm AS builder
LABEL org.opencontainers.image.source="https://github.com/reschjonas/leaktor"

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release --locked 2>/dev/null || cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/leaktor /usr/local/bin/leaktor

ENTRYPOINT ["leaktor"]
CMD ["--help"]

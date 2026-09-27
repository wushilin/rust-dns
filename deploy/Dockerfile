FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -u 10001 rust-dns && mkdir -p /data && chown rust-dns /data
COPY --from=build /src/target/release/rust-dns /usr/local/bin/rust-dns
USER rust-dns
WORKDIR /data
VOLUME /data
EXPOSE 53/udp 53/tcp 8053/tcp
ENTRYPOINT ["rust-dns", "--config", "/data/rust-dns.toml"]

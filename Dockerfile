FROM rust:1.83-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/box-fraise-chat /usr/local/bin/box-fraise-chat
COPY --from=build /app/migrations /migrations
ENV RUST_LOG=info
EXPOSE 8080
CMD ["box-fraise-chat"]

FROM rust:slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev python3 procps golang default-jdk-headless nodejs \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /w

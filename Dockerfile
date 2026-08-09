FROM rust:slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev python3 procps golang default-jdk-headless nodejs curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://bun.sh/install | bash \
    && ln -s /root/.bun/bin/bun /usr/local/bin/bun
WORKDIR /w

#!/bin/sh
# Builds and runs the full hangbook gate inside the Linux container.
set -e
cd "$(dirname "$0")/.."
docker build -q -t waitson-spike .
exec docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD":/w \
    -v waitson-cargo:/usr/local/cargo/registry \
    -v waitson-target:/w/target \
    waitson-spike \
    bash -c "cargo build --release -q && cargo test --release -q && python3 hangbook/harness.py"

#!/bin/sh
# Installs the latest waitson release binary.
# Usage: curl -fsSL https://raw.githubusercontent.com/hardy30894/waitson/main/install.sh | sh
set -eu

repo="${WAITSON_REPO:-hardy30894/waitson}"
install_dir="${WAITSON_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
    Darwin) os="apple-darwin" ;;
    Linux) os="unknown-linux-gnu" ;;
    *) echo "unsupported OS: $os (build from source: cargo install --git https://github.com/$repo waitson)" >&2; exit 1 ;;
esac
case "$arch" in
    arm64|aarch64) arch="aarch64" ;;
    x86_64|amd64) arch="x86_64" ;;
    *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

target="$arch-$os"
url="https://github.com/$repo/releases/latest/download/waitson-$target.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "fetching waitson ($target)"
if ! curl -fsSL "$url" -o "$tmp/waitson.tar.gz"; then
    echo "" >&2
    echo "no published binary at $url" >&2
    echo "if this project has not tagged a release yet, build it instead:" >&2
    echo "  cargo install --git https://github.com/$repo waitson" >&2
    exit 1
fi
tar -xzf "$tmp/waitson.tar.gz" -C "$tmp"

mkdir -p "$install_dir"
mv "$tmp/waitson" "$install_dir/waitson"
chmod +x "$install_dir/waitson"

echo "installed waitson to $install_dir/waitson"
case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) echo "note: $install_dir is not on your PATH; add it to use waitson directly" >&2 ;;
esac

# waitson reads /proc and process memory. Diagnosing another user's process,
# or your own under a hardened ptrace_scope, needs CAP_SYS_PTRACE or sudo.
echo "run 'waitson doctor' to check attach permissions on this machine"

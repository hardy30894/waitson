"""Fetch the waitson release binary matching this platform, then exec it.

The version tracks the package, which must match the git tag the release
was cut from. The binary is cached under the user cache dir so the download
happens once.
"""
import io
import os
import platform
import sys
import tarfile
import urllib.request

from . import __version__

REPO = os.environ.get("WAITSON_REPO", "hardy30894/waitson")


def _target():
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(
        platform.machine().lower()
    )
    sys_name = {"linux": "unknown-linux-gnu", "darwin": "apple-darwin"}.get(platform.system().lower())
    return f"{arch}-{sys_name}" if arch and sys_name else None


def _cache_path(target):
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "waitson", __version__, target, "waitson")


def _ensure_binary():
    target = _target()
    if not target:
        sys.exit(
            f"waitson: unsupported platform {platform.system()}/{platform.machine()}; "
            f"build from source: cargo install --git https://github.com/{REPO} waitson"
        )
    path = _cache_path(target)
    if os.path.exists(path):
        return path
    url = f"https://github.com/{REPO}/releases/download/v{__version__}/waitson-{target}.tar.gz"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with urllib.request.urlopen(url) as resp:
            data = resp.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            member = tar.getmember("waitson")
            with tar.extractfile(member) as src, open(path, "wb") as dst:
                dst.write(src.read())
        os.chmod(path, 0o755)
    except Exception as e:
        sys.exit(
            f"waitson: could not fetch the {target} binary ({e})\n  {url}\n"
            f"build from source: cargo install --git https://github.com/{REPO} waitson"
        )
    return path


def main():
    os.execv(_ensure_binary(), ["waitson", *sys.argv[1:]])


if __name__ == "__main__":
    main()

# Releasing waitson

A pushed `v*` tag builds the binaries and publishes every install path. All
three package versions must match the tag.

## One-time setup

- Repository secrets: `NPM_TOKEN` (npm automation token), `PYPI_TOKEN` (PyPI
  API token). GitHub release assets need no secret.
- Register the names once: `waitson` on crates.io, npm, and PyPI.

## Cutting a release

1. Bump the version in all three places to match the tag you will push:
   - `Cargo.toml` (`workspace.package.version`)
   - `npm/package.json`
   - `python/pyproject.toml` and `python/waitson/__init__.py`
2. Verify the suite is green: `./hangbook/run.sh`.
3. Commit, then tag and push:
   ```sh
   git tag v0.1.0
   git push origin main --tags
   ```

The tag fires `.github/workflows/release.yml`:

- **binaries** builds `x86_64`/`aarch64` × `linux`/`darwin` and attaches the
  tarballs to the GitHub release.
- **packages** publishes the npm and PyPI wrappers, which fetch those tarballs
  on install.

## How the install paths resolve

- `curl | sh` and the npm/PyPI wrappers all download
  `waitson-<target>.tar.gz` from `releases/download/v<version>/`.
- `cargo install --git` and `cargo install waitson` build from source and need
  no release assets.

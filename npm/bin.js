#!/usr/bin/env node
const path = require("path");
const { spawnSync } = require("child_process");

const bin = path.join(__dirname, "bin", "waitson");
const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (r.error) {
  console.error(`waitson: binary not found; reinstall the package (${r.error.message})`);
  process.exit(2);
}
process.exit(r.status === null ? 1 : r.status);

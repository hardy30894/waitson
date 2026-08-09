// Downloads the waitson release binary matching this platform. The version
// tracks package.json, which must match the git tag the release was cut from.
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const { execFileSync } = require("child_process");

const repo = process.env.WAITSON_REPO || "hardy30894/waitson";
const version = require("./package.json").version;

const target = (() => {
  const arch = { x64: "x86_64", arm64: "aarch64" }[process.arch];
  const sys = { linux: "unknown-linux-gnu", darwin: "apple-darwin" }[process.platform];
  return arch && sys ? `${arch}-${sys}` : null;
})();

if (!target) {
  console.error(`waitson: unsupported platform ${process.platform}/${process.arch}`);
  console.error("build from source instead: cargo install --git https://github.com/" + repo + " waitson");
  process.exit(0);
}

const url = `https://github.com/${repo}/releases/download/v${version}/waitson-${target}.tar.gz`;
const dir = path.join(__dirname, "bin");
const tmp = path.join(os.tmpdir(), `waitson-${version}-${target}.tar.gz`);

function download(u, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error("too many redirects"));
    https
      .get(u, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(download(res.headers.location, dest, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
      })
      .on("error", reject);
  });
}

(async () => {
  try {
    fs.mkdirSync(dir, { recursive: true });
    await download(url, tmp);
    execFileSync("tar", ["-xzf", tmp, "-C", dir]);
    fs.chmodSync(path.join(dir, "waitson"), 0o755);
    fs.unlinkSync(tmp);
    console.log(`waitson ${version} installed; run 'waitson doctor' to check attach permissions`);
  } catch (e) {
    console.error(`waitson: could not fetch the ${target} binary (${e.message})`);
    console.error(`  ${url}`);
    console.error("build from source instead: cargo install --git https://github.com/" + repo + " waitson");
    process.exit(0);
  }
})();

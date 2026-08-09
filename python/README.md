# waitson

Point it at any process. It tells you what the process is waiting for.

```sh
pip install waitson
waitson <pid>
waitson doctor
```

One sentence, with the evidence, in a quarter of a second. Nothing to install in your app, nothing to restart. Diagnoses Python, Go, the JVM, and native C/C++/Rust; reads Node on request. Full documentation: https://github.com/hardy30894/waitson

This package fetches the prebuilt `waitson` binary for your platform from the project's GitHub releases on first run. Linux and macOS; attaching follows the kernel's normal rules (`waitson doctor` explains what applies on your machine).

# Contributing to waitson

The best contribution is a hang waitson gets wrong, made reproducible.

## The hangbook is the test suite

Every diagnosis waitson can make is pinned by a scenario in `hangbook/scenarios/`: a small program that gets stuck in one documented way, plus a row in `hangbook/harness.py` asserting the verdict class, the root-cause words, and a latency bound. `./hangbook/run.sh` builds everything and scores the matrix inside a Linux container, so you can run it on any machine with Docker.

A scenario that produces a wrong verdict, a refusal where a verdict was possible, or a plausible-but-wrong causal chain is the highest-value bug report there is. Send the scenario even without a fix.

## Adding a scenario

1. Write the smallest program that reproduces the hang in `hangbook/scenarios/`. Print `READY <pid>` on stdout once it is stuck, then block.
2. Add a row to `SCENARIOS` in `hangbook/harness.py`: the command, the expected verdict class, and the substrings the verdict must contain.
3. Run `./hangbook/run.sh`. Your row should pass if waitson already handles the shape, or fail loudly if it does not.

## The rules the code holds

- **Verdict or refusal, never a guess.** If the evidence does not support a causal chain, refuse and show what was seen. A confident wrong answer is the one unacceptable outcome.
- **Derive, do not hardcode.** Offsets come from the target's own DWARF, wait reasons from the runtime's own tables, frame sizes from the runtime's own pcsp data. A magic constant that a future runtime release can break does not belong here.
- **Read-only, do no harm.** Waitson samples and detaches; it never writes to, injects into, or stops a target. The `overhead` hangbook row measures this and gates on it.
- **Runtimes plug in behind a trait.** A new language reader implements the same seam Python, Go, and the JVM already use; the core does not change to accommodate it.

## What waitson deliberately does not do yet

- **Node/V8 stacks.** V8 keeps the JavaScript stack in JIT-managed memory with no supported out-of-process layout. Waitson detects Node and refuses with that reason. A real reader would need to track V8's internal frame format, which changes without notice; until that exists, a guess is worse than a refusal.
- **asyncio / tokio pending-task graphs.** Waitson diagnoses the common asyncio freeze — a synchronous call made on the event loop, named down to the coroutine — from the Python stack it can read. Reconstructing "which pending task awaits which" is different: it means walking the loop's private task registry and each coroutine's await chain out of raw CPython memory, with no supported external interface, so a subtly wrong read produces a plausible-but-wrong graph. That part stays unbuilt until it can be validated against ground truth. tokio has no external scheduler introspection at all without instrumentation (tokio-console); a native tokio program still gets its per-thread verdict.
- **V8 heap-object reading without cooperation.** Native C/C++/Rust unwinds use DWARF `.eh_frame` CFI (frame-pointer walk as fallback), validated against the thread's own `backtrace()` including binaries with no frame pointers. Reading a V8 JavaScript stack out of process without the inspector (the llnode path, via `v8dbg_*` postmortem constants) is deliberately not built: it means decoding pointer-compressed tagged objects through constants that shift every V8 release, the only ground truth to validate against is the inspector that `--cooperate` already uses, and a subtly wrong decode is a plausible-but-wrong stack. `--cooperate` is the supported reader for Node's JS stack; the postmortem decoder is a standing project with a real maintenance cost, not a drop-in.

## Platform validation status

The hangbook is validated on arm64 with glibc. The x86_64 code paths (syscall
tables, register-to-DWARF mappings) are exercised by CI on `ubuntu-latest`; the
syscall tables are additionally confirmed under emulation, but ptrace- and
py-spy-dependent paths (native unwind, GIL reads) need real x86_64 hardware,
which is what CI provides. waitson builds and runs on musl (Alpine); the lock
owner read handles both the glibc and musl mutex layouts. Other distros, libc
versions, and language runtimes are untested surface — a failing hangbook
scenario on your platform is the contribution we want.

## Before you open a PR

```sh
cargo clippy --all-targets -- -D warnings
cargo test --release
./hangbook/run.sh
```

All three must be clean.

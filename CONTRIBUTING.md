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
- **asyncio / tokio task graphs.** Reconstructing "which task awaits which" post-hoc means walking the event loop's private task registry (CPython object graph) or tokio's scheduler internals, neither of which is a supported external interface. Waitson gives the honest verdict it can prove — the loop is idle, or a specific OS thread is blocked on a specific resource — and does not draw a task graph it cannot verify. A correct reader here is welcome; a plausible-but-wrong one is not.
- **CFI-based native unwinds.** Native C/C++/Rust call chains are recovered by frame-pointer walk, validated against the thread's own `backtrace()`. That reaches user frames whenever frame pointers are intact but stops where a frame-pointer-less library breaks the chain. DWARF `.eh_frame` CFI unwinding is the robustness upgrade that would cross those gaps; it must validate against the same ground truth before it replaces the walk.

## Before you open a PR

```sh
cargo clippy --all-targets -- -D warnings
cargo test --release
./hangbook/run.sh
```

All three must be clean.

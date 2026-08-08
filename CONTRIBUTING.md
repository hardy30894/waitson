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

## Before you open a PR

```sh
cargo clippy --all-targets -- -D warnings
cargo test --release
./hangbook/run.sh
```

All three must be clean.

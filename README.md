<div align="center">

# waitson

**Point it at any process. It tells you what the process is waiting for.**

*One sentence, with the evidence, in a quarter of a second. Nothing to install in your app, nothing to restart.*

[![zero instrumentation](https://img.shields.io/badge/instrumentation-zero-2E7D32?style=flat-square)](#how-it-reads-a-process) [![verdict or refusal](https://img.shields.io/badge/verdict-or%20refusal%2C%20never%20a%20guess-3557C4?style=flat-square)](#verdicts-and-refusals) [![diagnosis in 0.3s](https://img.shields.io/badge/diagnosis-~0.3s-8A2BE2?style=flat-square)](#the-hangbook) [![tests passing](https://img.shields.io/badge/tests-passing-2E7D32?style=flat-square)](#the-hangbook) [![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-6A6F7A?style=flat-square)](LICENSE)

</div>

Something is stuck. A server hangs, a script never finishes, a process eats a core and says nothing. Every tool you have hands you raw data from one layer, stack samples here, socket tables there, and leaves the conclusion to you. Waitson reads the process from outside, walks the layers, and hands you the conclusion:

```
$ waitson 41337
waitson: pid 41337 (python3) — waiting on the GIL, held by thread 41343 running match (re/__init__.py:166)
  → main thread 41337 blocked in futex wait and does not own the GIL
  → thread 41343 owns the GIL and is executing match (re/__init__.py:166)
  evidence: GIL ownership read from the interpreter's runtime state
```

That process was "hung." It was actually a catastrophic regex on a background thread, named down to the stdlib line, read from the interpreter's memory of a process waitson had never seen before.

It follows the trail across process boundaries. Here a client is stuck on a database connection, and waitson diagnoses the other end of the socket too:

```
$ waitson 41501
waitson: pid 41501 (python3) — waiting on a reply from 127.0.0.1:5432 (postgres),
                               which is pid 41497 (python3) on this machine — deliberately sleeping (nanosleep)
  → thread 41501 blocked in recvfrom on fd 3
  → fd 3 is a tcp socket 127.0.0.1:50644 → 127.0.0.1:5432
  → the other end resolved to pid 41497 (python3) and was diagnosed one hop deep
```

Deadlocks are proven, not suspected. The lock cycle is read out of the mutexes' own memory:

```
$ waitson deadlock
waitson: pid 41522 (deadlock) — deadlock: thread 41522 and thread 41524 each hold a lock the other is waiting for
  evidence: lock cycle proven from glibc mutex owner fields
```

Go programs get diagnosed at the goroutine layer, because that is the only layer that tells the truth for Go. No per-version tables: struct offsets come from the binary's own DWARF, wait-reason names from the runtime's own string table:

```
$ waitson 41610
waitson: pid 41610 (api) — waiting at the Go level: the main goroutine is blocked in chan receive —
                           4 goroutines blocked, and only an external event can move it (still open: IO wait (main.listen))
  → 1× chan receive (runtime.main)
  → 3× chan send (main.worker)
```

And when nothing is wrong, it says so, which is also an answer:

```
$ waitson :8080
waitson: pid 41288 (python3) — asyncio event loop is idle — 1 fds registered, none with pending data, zero cpu
```

## Point it at whatever you know

```
waitson 41337        a pid
waitson uvicorn      a process name
waitson :5432        whoever owns that port on this machine
waitson scan         sweep the whole machine, diagnose what looks stuck in anger
waitson watch        stay resident; diagnose anything the moment it turns stuck
waitson doctor       explains attach permissions on this machine
```

`waitson scan` works in two phases so it stays honest and harmless fleet-wide: a no-attach sweep over kernel facts flags only what looks stuck in anger (uninterruptible sleep that persists, a core burning across the window), then just those suspects get the full diagnosis. On a healthy machine it says so and touches nothing.

A port target is not a network probe: waitson resolves the port to its owning local process and reads that process from inside the machine. When a trail ends at a remote host, the verdict says exactly that, and where to run waitson next.

## How it reads a process

Five blocks, one pass, all read-only:

1. **snap** freezes the kernel's view: every thread's state and wait channel, the syscall it is parked in with its arguments, the fd table, socket tables read through the target's own network namespace (containers resolve correctly), pipe endpoints across processes.
2. **read** opens the runtime: CPython stacks with GIL ownership and source lines read from process memory; Go goroutines with their wait reasons, offsets derived from the binary's own DWARF; JVM monitors through the JVM's own thread-dump mechanism.
3. **link** crosses boundaries: futex words are read back to their owner threads, pipes to their other ends, and a blocked local socket to the process on the other side, which gets diagnosed one hop deep.
4. **judge** walks the evidence to a verdict. Deterministic rules, no model, no guessing. The subject is the most-blocked thread, not just the main one, so an idle event loop never hides a stuck worker.
5. **tell** prints the sentence and the chain. `--json` emits the verdict plus the full wait graph for agents and CI.

The blocks compose like pipes: `waitson snap 41337 | waitson judge` captures the evidence in one step and judges it in another, so a snap can be shipped off a production box and judged elsewhere. Offline judging skips the live-only enrichments (the socket hop, the runtime readers) and says so.

Attaching is a brief sample-read-detach. Waitson never writes to the target, never injects, and its impact is measured, not asserted: the hangbook diagnoses a throughput-counting process four times in a row and requires the rate to stay within three sigma of its own baseline noise. Latest run: 1.55M iterations per 100ms baseline, 1.63M during diagnosis. No measurable dent. It is safe to point at production.

## Scripting

Exit codes are part of the contract: `0` a verdict was reached (causal, partial, or observation), `1` a refusal, `2` waitson itself could not run. So `waitson :8000 || alert` does what it reads like, and `--json` output is stable for machines.

## Verdicts and refusals

Every run ends in exactly one of four classes:

| class | meaning |
|---|---|
| `CAUSAL` | the full chain to a root cause, with evidence per step |
| `PARTIAL` | a true chain that ends at a named boundary ("trail ends at the wire") |
| `OBSERVATION` | nothing is stuck: busy, sleeping, or idle by design, and here is why |
| `REFUSAL` | it cannot be read truthfully, and here is exactly what is missing |

Refusals are a feature. Go programs, for example, multiplex goroutines over threads, so kernel-level facts cannot distinguish a stuck Go program from an idle one. Waitson detects a Go binary and refuses with that reason rather than shipping a plausible guess, until its goroutine reader exists.

## The hangbook

The test suite is a set of reproducible stuck programs, each with the verdict it must produce. Current matrix, every row measured on the real binary against the real hang:

| scenario | verdict | time |
|---|---|---|
| AB-BA mutex deadlock | CAUSAL, cycle proven from mutex memory | 0.26s |
| lock held by a busy thread | CAUSAL, owner named | 0.26s |
| stuck database call | CAUSAL, peer process diagnosed one hop deep | 0.40s |
| DNS query never answered | PARTIAL, trail ends at the wire | 0.27s |
| write on a full pipe | CAUSAL, absent reader named | 0.27s |
| GIL held by a hot thread | CAUSAL, holder's source line named | 0.26s |
| vfork parent in D state | CAUSAL, child named | 0.26s |
| busy loop | OBSERVATION, source line named | 0.26s |
| wait on a SIGSTOPped child | CAUSAL, resume command given | 0.28s |
| idle asyncio event loop | OBSERVATION, idle by design | 0.26s |
| target by `:port` | resolves the owner and diagnoses it | 0.27s |
| Go channels wedged | PARTIAL, main goroutine's wait reason named | 0.29s |
| stripped Go binary | REFUSAL, with the rebuild flag that fixes it | 0.27s |
| worker stuck behind an idle main thread | CAUSAL, the most-blocked thread is the story | 0.43s |
| blocked on a file lock | CAUSAL, holder pid and the actual file path named | 0.30s |
| Java monitor deadlock | CAUSAL, cycle proven from the JVM's own thread dump | 0.53s |
| machine sweep | `scan` flags D-state, busy loop, and unread socket data; spares the idle loop | 0.91s |
| hang introduced under `watch` | flagged at onset, unprompted, in under a second | 0.98s |
| `snap \| judge` pipeline | same verdict class offline, exit code honored | 0.27s |
| do-no-harm under 4 diagnoses | target throughput within 3 sigma of its own baseline | measured |

Reproduce it: `./hangbook/run.sh` builds everything and scores the matrix in a container. Scenarios that expose a wrong or missing verdict are the contribution we want most.

## Build from source

```sh
git clone https://github.com/hardy30894/waitson && cd waitson
cargo build --release        # target/release/waitson
```

Waitson reads `/proc` and process memory, so diagnosis runs on Linux today (on macOS, run it inside the container where your workload lives). Attaching follows the kernel's normal rules: your own processes with `ptrace_scope 0`, otherwise `sudo` or `CAP_SYS_PTRACE`; `waitson doctor` tells you which applies on your machine.

## License

Apache 2.0.

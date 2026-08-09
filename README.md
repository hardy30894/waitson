<div align="center">

# waitson

**Point it at any process. It tells you what the process is waiting for.**

*One sentence, with the evidence, in a quarter of a second. Nothing to install in your app, nothing to restart. Linux fully, macOS natively.*

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
  → 3× chan send in main.worker (api/worker.go:26), spawned from main.main (api/main.go:31)
       — blocked at main.send (api/worker.go:83) ← main.process (api/worker.go:41) ← main.worker (api/worker.go:26)
  → 1× IO wait in main.listen (api/server.go:88)
```

Which line is stuck, the call chain that got there — inlined frames expanded and all — and the `go` statement that started it, resolved from the binary's own gopclntab and unwound with the runtime's own pcsp and inline tables. The unwinder is held against `runtime.Stack` ground truth in the test suite: waitson's frames must match the runtime's own report of the same process, frame for frame including inlined calls, or the suite fails.

Runtimes with no supported external reader get a refusal, not a guess. A Node/V8 process (JavaScript stack in JIT memory) and a stripped Go binary both say exactly why they can't be read and what would fix it — waitson never invents a call stack it cannot see.

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
2. **read** opens the runtime: CPython stacks with GIL ownership and source lines read from process memory; Go goroutines with their wait reasons, offsets derived from the binary's own DWARF; JVM monitors through the JVM's own thread-dump mechanism; native C/C++/Rust call chains unwound from the blocked thread's registers by the compiler's own `.eh_frame` tables, so they work even in release code with no frame pointers, symbolized per module.
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

Refusals are a feature. A parked Node or Bun process keeps its JavaScript stack in JIT memory with no supported external reader, so a kernel-level verdict would miss the real cause; waitson detects the runtime, names the engine, and refuses rather than shipping a plausible guess. A Go binary stripped of its symbols gets the same treatment, naming the build flag that would fix it. Waitson never invents a stack it cannot see.

For Node there is one opt-in step further: `waitson <pid> --cooperate` activates the target's own inspector (the same SIGUSR1 mechanism `node --inspect` uses), pauses V8, and names the JavaScript line that never returns to the event loop:

```
$ waitson 41712 --cooperate
waitson: pid 41712 (node) — wedged executing JavaScript: retryLoop (api/queue.js:83) never returns to the event loop
```

It is the one mode that touches the target, and it says so: the debug port stays open afterward. If no JavaScript is executing at all, it says that instead, which rules out a JS wedge in one command.

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
| Go inlined call chain | frames match `runtime.Stack`, inlined calls expanded | 0.29s |
| native C thread through libc | call chain matches the thread's own `backtrace()`, in order | measured |
| native thread with no frame pointers | `.eh_frame` CFI recovers the chain fp-walk can't | measured |
| stripped Go binary | REFUSAL, with the rebuild flag that fixes it | 0.27s |
| Node/V8 process | REFUSAL, JS stack lives in JIT memory, reason named | 0.30s |
| worker stuck behind an idle main thread | CAUSAL, the most-blocked thread is the story | 0.43s |
| blocked on a file lock | CAUSAL, holder pid and the actual file path named | 0.30s |
| Java monitor deadlock | CAUSAL, cycle proven from the JVM's own thread dump | 0.53s |
| Node spin loop under `--cooperate` | CAUSAL, the JS line named via Node's own inspector | measured |
| idle Node under `--cooperate` | OBSERVATION, no JS executing, rules out a JS wedge | measured |
| machine sweep | `scan` flags D-state, busy loop, and unread socket data; spares the idle loop | 0.91s |
| hang introduced under `watch` | flagged at onset, unprompted, in under a second | 0.98s |
| `snap \| judge` pipeline | same verdict class offline, exit code honored | 0.27s |
| do-no-harm under 4 diagnoses | target throughput within 3 sigma of its own baseline | measured |
| goroutine stack unwind | frames match `runtime.Stack` ground truth, in order | 0.30s |

Reproduce it: `./hangbook/run.sh` builds everything and scores the matrix in a container. Scenarios that expose a wrong or missing verdict are the contribution we want most.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/hardy30894/waitson/main/install.sh | sh
```

One static binary, no runtime, no account. Then `waitson doctor` checks attach permissions on your machine.

## Build from source

```sh
git clone https://github.com/hardy30894/waitson && cd waitson
cargo build --release        # target/release/waitson
```

Linux is the full experience: `/proc` and process memory give waitson every layer, and attaching follows the kernel's normal rules (your own processes with `ptrace_scope 0`, otherwise `sudo` or `CAP_SYS_PTRACE`). macOS runs a native tier with honest edges: thread states, cpu attribution, and socket endpoints come through `libproc` with no sudo at all, so busy/stopped/uninterruptible verdicts work on your own processes out of the box; wait *causes* and Python internals need memory reads, which macOS grants only under sudo; `scan`, `watch`, and name/`:port` targeting are Linux-only for now. Where the cause is invisible, waitson refuses and shows what it did see rather than guessing. `waitson doctor` tells you exactly which tier applies on your machine.

## Contributing

The best contribution is a hang waitson gets wrong, made reproducible as a hangbook scenario. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0.

<div align="center">

# waitson

**Point it at any process. It tells you what the process is waiting for.**

*A hung process explained in one sentence, in a quarter of a second, whatever language it is written in.*

[![zero instrumentation](https://img.shields.io/badge/instrumentation-zero-2E7D32?style=flat-square)](#how-it-reads-a-process) [![verdict or refusal](https://img.shields.io/badge/verdict-or%20refusal%2C%20never%20a%20guess-3557C4?style=flat-square)](#verdicts-and-refusals) [![across processes](https://img.shields.io/badge/follows%20the%20wait-across%20processes-8A2BE2?style=flat-square)](#it-crosses-boundaries) [![tests passing](https://img.shields.io/badge/hangbook-29%2F29-2E7D32?style=flat-square)](#the-hangbook) [![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-6A6F7A?style=flat-square)](LICENSE)

</div>

Something is stuck. A server stops answering, a script never returns, a process eats a core and says nothing. Every tool you own hands you raw material from one layer, stack samples here, a socket table there, and leaves the conclusion to you. Waitson reads the process from outside, walks the layers, and hands you the conclusion:

```
$ waitson 41337
waitson: pid 41337 (python3) — waiting on the GIL, held by thread 41343 running match (re/__init__.py:166)
  → main thread 41337 blocked in futex wait and does not own the GIL
  → thread 41343 owns the GIL and is executing match (re/__init__.py:166)
  evidence: GIL ownership read from the interpreter's runtime state
```

That process was "hung." It was a catastrophic regex on a background thread, named down to the stdlib line, read from the interpreter's own memory, on a process waitson had never seen before and with nothing installed ahead of time.

**This is not a profiler, and not a stack dumper.** perf and gdb hand an expert a flamegraph or a register dump and wish them luck. py-spy dumps a Python stack, jstack dumps Java threads, and each one stops at a single process in a single language. Waitson computes the cause, in one command, whatever the process is written in, and it follows the wait across the boundary: through a lock to the thread that holds it, through a socket to the process on the other end. Nothing is guessed. Every verdict carries the evidence it was read from, and where the truth cannot be read, waitson refuses instead of inventing one.

**Contents**: [Install](#install) · [Point it at whatever you know](#point-it-at-whatever-you-know) · [When you reach for it](#when-you-reach-for-it) · [It crosses boundaries](#it-crosses-boundaries) · [Every runtime, read honestly](#every-runtime-read-honestly) · [How it reads a process](#how-it-reads-a-process) · [Verdicts and refusals](#verdicts-and-refusals) · [Scripting](#scripting) · [The hangbook](#the-hangbook) · [Build from source](#build-from-source)

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/hardy30894/waitson/main/install.sh | sh
```

or through your package manager:

```sh
npm install -g waitson      # or: pip install waitson
```

One static binary, no runtime, no account, no config. Then `waitson doctor` checks attach permissions on your machine.

## Point it at whatever you know

```
waitson 41337        a pid
waitson uvicorn      a process name
waitson :5432        whoever owns that port on this machine
waitson scan         sweep the whole machine, diagnose what looks stuck in anger
waitson watch        stay resident, diagnose anything the moment it turns stuck
waitson doctor       explains attach permissions on this machine
```

A port target is not a network probe. Waitson resolves the port to its owning local process and reads that process from inside the machine. When a trail ends at a remote host, the verdict says exactly that, and where to run waitson next.

## When you reach for it

You reach for it the moment a process is stuck or silent and you want the cause now, not a data dump to interpret at 2am.

- A production service stops responding, and you do not yet know which process, which thread, or which language is the culprit.
- A script never finishes, a CI job wedges, a dev server freezes.
- You need to know whether something is genuinely stuck, or just idle by design, or busy-looping. That is often the whole question, and a metric graph will not answer it.
- Two services are deadlocked across a socket, and the story spans both processes.

If you live in one language and hit single-process hangs, that language's own tool is enough. Waitson earns its place when the hang spans processes or runtimes, or when you would rather have the conclusion than spend ten minutes juggling five tools to assemble it yourself.

## It crosses boundaries

A single-process, single-language tool stops where the wait leaves the process. Waitson keeps going. Here a client is stuck on a database connection, and waitson diagnoses the process on the other end of the socket too:

```
$ waitson 41501
waitson: pid 41501 (python3) — waiting on a reply from 127.0.0.1:5432 (postgres),
                               which is pid 41497 (python3) on this machine — deliberately sleeping (nanosleep)
  → thread 41501 blocked in recvfrom on fd 3
  → fd 3 is a tcp socket 127.0.0.1:50644 → 127.0.0.1:5432
  → the other end resolved to pid 41497 (python3) and was diagnosed one hop deep
```

Following that trail by hand means running py-spy, then reading a socket table, then resolving a pid, then picking that process's language and running its tool, then stitching the two together. Waitson does the whole chain in one command, and it does it whether the two ends are Python, Go, or native.

Deadlocks are proven, not suspected. The lock cycle is read out of the mutexes' own memory:

```
$ waitson deadlock
waitson: pid 41522 (deadlock) — deadlock: thread 41522 and thread 41524 each hold a lock the other is waiting for
  evidence: lock cycle proven from glibc mutex owner fields
```

## Every runtime, read honestly

Waitson auto-detects the runtime and reads it the way that runtime tells the truth, deriving everything from the process itself rather than from a table of hardcoded constants.

**Go** is diagnosed at the goroutine layer, because that is the only layer that is true for Go. Struct offsets come from the binary's own DWARF, wait reasons from the runtime's own string table, and the call chain is unwound with the runtime's own pcsp and inline tables:

```
$ waitson 41610
waitson: pid 41610 (api) — waiting at the Go level: the main goroutine is blocked in chan receive —
                           4 goroutines blocked, and only an external event can move it (still open: IO wait (main.listen))
  → 3× chan send in main.worker (api/worker.go:26), spawned from main.main (api/main.go:31)
       — blocked at main.send (api/worker.go:83) ← main.process (api/worker.go:41) ← main.worker (api/worker.go:26)
  → 1× IO wait in main.listen (api/server.go:88)
```

The unwinder is held against `runtime.Stack` ground truth in the test suite: waitson's frames must match the runtime's own report of the same process, frame for frame including inlined calls, or the suite fails.

**Python** gets the GIL holder and, when a synchronous call freezes an asyncio event loop, the coroutine responsible:

```
$ waitson 41780
waitson: pid 41780 (python3) — the asyncio event loop is frozen: a blocking call in handler (app/svc.py:88) is stalling every task
```

**Native C, C++, and Rust** are unwound from the blocked thread's registers using the compiler's own `.eh_frame` tables, so the call chain is recovered even in release code with no frame pointers, and validated against the thread's own `backtrace()`. **Java** deadlocks are proven from the JVM's own thread dump.

When nothing is wrong, it says so, which is also an answer:

```
$ waitson :8080
waitson: pid 41288 (python3) — asyncio event loop is idle — 1 fds registered, none with pending data, zero cpu
```

## How it reads a process

Five blocks, one pass, all read-only:

1. **snap** freezes the kernel's view: every thread's state and wait channel, the syscall it is parked in with its arguments, the fd table, socket tables read through the target's own network namespace so containers resolve correctly, pipe endpoints across processes.
2. **read** opens the runtime: CPython stacks with GIL ownership and source lines from process memory, Go goroutines with wait reasons and offsets from the binary's own DWARF, JVM monitors through the JVM's own thread dump, native call chains from `.eh_frame` CFI, symbolized per module.
3. **link** crosses boundaries: futex words to their owner threads, pipes to their other ends, a blocked local socket to the process on the far side, which gets diagnosed one hop deep.
4. **judge** walks the evidence to a verdict. Deterministic rules, no model, no guessing. The subject is the most-blocked thread, not just the main one, so an idle event loop never hides a stuck worker.
5. **tell** prints the sentence and the chain. `--json` emits the verdict plus the full wait graph for agents and CI.

The blocks compose like pipes. `waitson snap 41337 | waitson judge` captures the evidence in one step and judges it in another, so a snapshot can be shipped off a production box and judged elsewhere.

Attaching is a brief sample-read-detach. Waitson never writes to the target, never injects, and its impact is measured rather than asserted: the hangbook diagnoses a throughput-counting process four times in a row and requires its rate to stay within three sigma of its own baseline noise. Latest run, 1.55M iterations per 100ms baseline against 1.63M during diagnosis. No measurable dent. It is safe to point at production.

## Verdicts and refusals

Every run ends in exactly one of four classes:

| class | meaning |
|---|---|
| `CAUSAL` | the full chain to a root cause, with evidence per step |
| `PARTIAL` | a true chain that ends at a named boundary, "trail ends at the wire" |
| `OBSERVATION` | nothing is stuck: busy, sleeping, or idle by design, and here is why |
| `REFUSAL` | it cannot be read truthfully, and here is exactly what is missing |

Refusals are a feature. A parked Node or Bun process keeps its JavaScript stack in JIT memory with no supported external reader, so a kernel-level verdict would miss the real cause. Waitson detects the runtime, names the engine, and refuses rather than ship a plausible guess. A Go binary stripped of its symbols gets the same treatment, naming the build flag that would fix it. Waitson never invents a stack it cannot see.

For Node there is one opt-in step further. `waitson <pid> --cooperate` activates the target's own inspector, the same SIGUSR1 mechanism `node --inspect` uses, pauses V8, and names the JavaScript line that never returns to the event loop:

```
$ waitson 41712 --cooperate
waitson: pid 41712 (node) — wedged executing JavaScript: retryLoop (api/queue.js:83) never returns to the event loop
```

It is the one mode that touches the target, and it says so, because the debug port stays open afterward. If no JavaScript is executing at all, it says that instead, which rules out a JS wedge in one command.

## Scripting

Exit codes are part of the contract: `0` a verdict was reached, `1` a refusal, `2` waitson itself could not run. So `waitson :8000 || alert` does what it reads like, and `--json` output is stable for machines and agents.

`waitson scan` and `waitson watch` cover a whole machine. Both work in two phases so they stay honest and harmless fleet-wide: a no-attach sweep over kernel facts flags only what looks stuck in anger, uninterruptible sleep that persists or a core burning across the window, and only those suspects get the full diagnosis. On a healthy machine, scan says so and touches nothing.

## The hangbook

The test suite is a set of reproducible stuck programs, each with the verdict it must produce. Every row is measured on the real binary against the real hang, and where the answer is a stack, it is checked frame for frame against the runtime's own ground truth.

| scenario | verdict | time |
|---|---|---|
| AB-BA mutex deadlock | CAUSAL, cycle proven from mutex memory | 0.26s |
| lock held by a busy thread | CAUSAL, owner named | 0.26s |
| stuck database call | CAUSAL, peer process diagnosed one hop deep | 0.40s |
| DNS query never answered | PARTIAL, trail ends at the wire | 0.27s |
| write on a full pipe | CAUSAL, absent reader named | 0.27s |
| GIL held by a hot thread | CAUSAL, holder's source line named | 0.26s |
| asyncio loop frozen by a sync call | CAUSAL, the blocking coroutine named | 0.30s |
| idle asyncio event loop | OBSERVATION, idle by design | 0.26s |
| vfork parent in D state | CAUSAL, child named | 0.26s |
| busy loop | OBSERVATION, source line named | 0.26s |
| wait on a SIGSTOPped child | CAUSAL, resume command given | 0.28s |
| worker stuck behind an idle main thread | CAUSAL, the most-blocked thread is the story | 0.43s |
| blocked on a file lock | CAUSAL, holder pid and the actual file path named | 0.30s |
| target by `:port` | resolves the owner and diagnoses it | 0.27s |
| Go channels wedged | PARTIAL, main goroutine's wait reason named | 0.29s |
| Go goroutine stack unwind | frames match `runtime.Stack`, in order | 0.30s |
| Go inlined call chain | inlined frames expanded, matches `runtime.Stack` | 0.29s |
| stripped Go binary | REFUSAL, with the rebuild flag that fixes it | 0.27s |
| native C thread through libc | call chain matches the thread's own `backtrace()` | measured |
| native thread with no frame pointers | `.eh_frame` CFI recovers the chain fp-walk cannot | measured |
| Java monitor deadlock | CAUSAL, cycle proven from the JVM's own thread dump | 0.53s |
| Node/V8 or Bun process | REFUSAL, JS stack lives in JIT memory, reason named | 0.30s |
| Node spin loop under `--cooperate` | CAUSAL, the JS line named via Node's own inspector | measured |
| idle Node under `--cooperate` | OBSERVATION, no JS executing, rules out a JS wedge | measured |
| machine sweep | `scan` flags D-state, busy loop, and unread socket data, spares the idle loop | 0.91s |
| hang introduced under `watch` | flagged at onset, unprompted, in under a second | 0.98s |
| `snap \| judge` pipeline | same verdict class offline, exit code honored | 0.27s |
| do-no-harm under 4 diagnoses | target throughput within three sigma of its own baseline | measured |

Reproduce it with `./hangbook/run.sh`, which builds everything and scores the matrix in a container. A scenario that exposes a wrong or missing verdict is the contribution we want most.

## Build from source

```sh
git clone https://github.com/hardy30894/waitson && cd waitson
cargo build --release        # target/release/waitson
```

Linux is the full experience. `/proc` and process memory give waitson every layer, and attaching follows the kernel's normal rules: your own processes with `ptrace_scope 0`, otherwise `sudo` or `CAP_SYS_PTRACE`. macOS runs a native tier with honest edges: thread states, cpu attribution, and socket endpoints come through `libproc` with no sudo, so busy, stopped, and uninterruptible verdicts work on your own processes out of the box, while wait causes and Python internals need memory reads that macOS grants only under sudo, and `scan`, `watch`, and name or `:port` targeting are Linux-only for now. `waitson doctor` tells you exactly which tier applies on your machine.

A stripped binary symbolizes to `module+offset`. Set `DEBUGINFOD_URLS` and waitson uses the standard `debuginfod-find` client to fetch the separate debug symbols and name the frames.

## Contributing

The best contribution is a hang waitson gets wrong, made reproducible as a hangbook scenario. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0.

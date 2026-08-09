#!/usr/bin/env python3
"""Hangbook: canonical hangs, one verdict each.

Pass = expected verdict class, expected root-cause words, under 3 seconds.
The v0.0 spike gate (>=8/10) is passed and this is now the regression
suite: every scenario must pass.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(ROOT, "..", "target", "release", "waitson")
BUILD = "/tmp/hb"

# (name, cmd, expected class, required substrings, target override)
# A target of None diagnoses the pid the scenario prints; a string like
# ":5432" exercises target resolution against the same live scenario.
SCENARIOS = [
    ("deadlock", [f"{BUILD}/deadlock"], "CAUSAL", [["deadlock"]], None),
    ("lockbusy", [f"{BUILD}/lockbusy"], "CAUSAL", [["held by"], ["busy", "running"]], None),
    ("slowdb", [sys.executable, "scenarios/slowdb.py"], "CAUSAL", [["5432", "postgres"], ["sleep"]], None),
    ("dnsstall", [sys.executable, "scenarios/dnsstall.py"], "PARTIAL", [["dns", ":53"]], None),
    ("pipefull", [sys.executable, "scenarios/pipefull.py"], "CAUSAL", [["pipe"]], None),
    ("gil", [sys.executable, "scenarios/gil.py"], "CAUSAL", [["gil"]], None),
    ("dstate", [f"{BUILD}/dstate"], "CAUSAL", [["vfork"]], None),
    ("busyloop", [sys.executable, "scenarios/busyloop.py"], "OBSERVATION", [["busy"]], None),
    ("childwait", [sys.executable, "scenarios/childwait.py"], "CAUSAL", [["stopped"]], None),
    ("epollidle", [sys.executable, "scenarios/epollidle.py"], "OBSERVATION", [["idle"], ["asyncio"]], None),
    ("porttarget", [sys.executable, "scenarios/slowdb.py"], "OBSERVATION", [["sleep"]], ":5432"),
    ("gochan", [f"{BUILD}/gochan"], "PARTIAL", [["goroutine"], ["chan receive"], ["gochan.go:"]], None),
    ("gostripped", [f"{BUILD}/gostripped"], "REFUSAL", [["stripped"]], None),
    ("threadstuck", [sys.executable, "scenarios/threadstuck.py"], "CAUSAL", [["9009"], ["sleep"], ["most-blocked"]], None),
    ("flocked", [sys.executable, "scenarios/flocked.py"], "CAUSAL", [["file lock"], ["held by"], ["lockfile"]], None),
    ("jdeadlock", ["java", "-cp", BUILD, "Deadlock"], "CAUSAL", [["java-level deadlock"], ["left"], ["right"]], None),
    ("nodehang", ["node", "scenarios/nodehang.js"], "REFUSAL", [["node"], ["jit"]], None),
    ("nodeblocked", ["node", "scenarios/nodeblocked.js"], "CAUSAL", [["pipe"], ["held by"]], None),
    ("bunhang", ["bun", "scenarios/nodehang.js"], "REFUSAL", [["bun"], ["javascriptcore"]], None),
]


def build_c():
    os.makedirs(BUILD, exist_ok=True)
    for src in ("deadlock", "lockbusy", "dstate"):
        subprocess.run(
            ["gcc", "-O0", "-pthread", os.path.join(ROOT, "scenarios", f"{src}.c"), "-o", f"{BUILD}/{src}"],
            check=True,
        )
    goenv = {**os.environ, "GOCACHE": "/tmp/gocache"}
    src = os.path.join(ROOT, "scenarios", "gochan.go")
    subprocess.run(["go", "build", "-o", f"{BUILD}/gochan", src], env=goenv, check=True)
    subprocess.run(
        ["go", "build", "-ldflags", "-s -w", "-o", f"{BUILD}/gostripped", src], env=goenv, check=True
    )
    subprocess.run(
        ["go", "build", "-o", f"{BUILD}/gostacks", os.path.join(ROOT, "scenarios", "gostacks.go")],
        env=goenv, check=True,
    )
    subprocess.run(["javac", "-d", BUILD, os.path.join(ROOT, "scenarios", "Deadlock.java")], check=True)


def read_ready(proc, timeout=10.0):
    result = {}

    def reader():
        line = proc.stdout.readline()
        if line.startswith("READY "):
            result["pid"] = int(line.split()[1])

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(timeout)
    return result.get("pid")


def run_one(name, cmd, expected, needles, target_override):
    # stdin is a held-open pipe so scenarios that block reading it stay blocked.
    proc = subprocess.Popen(
        cmd, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, start_new_session=True,
    )
    row = {"name": name, "expected": expected, "passed": False}
    try:
        target = read_ready(proc)
        if target is None:
            row["error"] = "scenario never printed READY"
            return row
        if target_override is not None:
            target = target_override
        time.sleep(0.8)

        t0 = time.monotonic()
        out = subprocess.run([BIN, str(target), "--json"], capture_output=True, text=True, timeout=10)
        row["seconds"] = round(time.monotonic() - t0, 2)
        if out.returncode not in (0, 1):
            row["error"] = out.stderr.strip()
            return row

        verdict = json.loads(out.stdout)["verdict"]
        row["class"] = verdict["class"]
        row["headline"] = verdict["headline"]
        text = json.dumps(verdict).lower()
        row["passed"] = (
            verdict["class"] == expected
            and all(any(n.lower() in text for n in group) for group in needles)
            and row["seconds"] < 3.0
        )
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()


def run_scan_row():
    """Launch a D-state hang, a busy loop, a server sitting on unread
    socket data, and a healthy idle loop; scan must flag the first three
    and leave the healthy one alone."""
    row = {"name": "scan", "expected": "FINDINGS", "passed": False}
    procs = {}
    try:
        for name, cmd in [
            ("dstate", [f"{BUILD}/dstate"]),
            ("busyloop", [sys.executable, "scenarios/busyloop.py"]),
            ("scanunread", [sys.executable, "scenarios/scanunread.py"]),
            ("epollidle", [sys.executable, "scenarios/epollidle.py"]),
        ]:
            p = subprocess.Popen(
                cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True
            )
            procs[name] = (p, read_ready(p))
        if any(pid is None for _, pid in procs.values()):
            row["error"] = "a scan scenario never printed READY"
            return row
        time.sleep(0.8)

        t0 = time.monotonic()
        out = subprocess.run([BIN, "scan", "--json"], capture_output=True, text=True, timeout=15)
        row["seconds"] = round(time.monotonic() - t0, 2)
        found = {f["pid"] for f in json.loads(out.stdout)["findings"]}
        flagged_d = procs["dstate"][1] in found
        flagged_busy = procs["busyloop"][1] in found
        flagged_unread = procs["scanunread"][1] in found
        spared_idle = procs["epollidle"][1] not in found
        row["class"] = f"flagged {len(found)}"
        row["headline"] = (
            f"dstate {'flagged' if flagged_d else 'MISSED'}, busyloop {'flagged' if flagged_busy else 'MISSED'}, "
            f"unread-socket {'flagged' if flagged_unread else 'MISSED'}, idle {'spared' if spared_idle else 'WRONGLY FLAGGED'}"
        )
        row["passed"] = flagged_d and flagged_busy and flagged_unread and spared_idle
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        for p, _ in procs.values():
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            p.wait()


def run_watch_row():
    """Start the sentinel on a quiet machine, then introduce a busy loop;
    watch must emit a finding for it at onset, unprompted."""
    row = {"name": "watch", "expected": "ONSET", "passed": False}
    watcher = subprocess.Popen(
        [BIN, "watch", "--json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True
    )
    hog = None
    try:
        time.sleep(1.2)
        hog = subprocess.Popen(
            [sys.executable, "scenarios/busyloop.py"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
        )
        hog_pid = read_ready(hog)
        t0 = time.monotonic()
        events = {}

        def reader():
            for line in watcher.stdout:
                try:
                    ev = json.loads(line)
                    events[ev["pid"]] = ev
                except (ValueError, KeyError):
                    pass
                if hog_pid in events:
                    return

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(8)
        row["seconds"] = round(time.monotonic() - t0, 2)
        ev = events.get(hog_pid)
        if ev is None:
            row["error"] = f"watch never flagged the busy loop (events: {list(events)})"
            return row
        row["class"] = "onset"
        row["headline"] = ev["headline"]
        row["passed"] = "busy" in ev["headline"].lower()
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        for p in (watcher, hog):
            if p is not None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                p.wait()


def run_cooperate_rows():
    """--cooperate on a JS spin loop must name the JS line via the
    inspector; on an idle loop it must say no JS is executing."""
    rows = []
    for name, script, expected, needles in [
        ("coop-spin", "scenarios/nodespin.js", "CAUSAL", [["nodespin.js"], ["javascript"]]),
        ("coop-idle", "scenarios/nodehang.js", "OBSERVATION", [["no javascript"]]),
    ]:
        row = {"name": name, "expected": expected, "passed": False}
        proc = subprocess.Popen(
            ["node", script], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
        )
        try:
            target = read_ready(proc)
            if target is None:
                row["error"] = "scenario never printed READY"
                continue
            time.sleep(0.8)
            t0 = time.monotonic()
            out = subprocess.run(
                [BIN, str(target), "--cooperate", "--json"], capture_output=True, text=True, timeout=15
            )
            row["seconds"] = round(time.monotonic() - t0, 2)
            verdict = json.loads(out.stdout)["verdict"]
            row["class"] = verdict["class"]
            row["headline"] = verdict["headline"]
            text = json.dumps(verdict).lower()
            row["passed"] = verdict["class"] == expected and all(
                any(n.lower() in text for n in group) for group in needles
            )
        except Exception as e:
            row["error"] = repr(e)
        finally:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
            rows.append(row)
    return rows


def run_gounwind_row():
    """Waitson's goroutine unwind, held against runtime.Stack ground truth:
    the a->b->c chain must appear in the verdict in the same order the
    runtime itself reports."""
    row = {"name": "gounwind", "expected": "GROUNDTRUTH", "passed": False}
    proc = subprocess.Popen(
        [f"{BUILD}/gostacks"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
    )
    try:
        target = read_ready(proc)
        if target is None:
            row["error"] = "scenario never printed READY"
            return row
        time.sleep(0.8)
        t0 = time.monotonic()
        out = subprocess.run([BIN, str(target), "--json"], capture_output=True, text=True, timeout=10)
        row["seconds"] = round(time.monotonic() - t0, 2)
        verdict = json.loads(out.stdout)["verdict"]
        text = json.dumps(verdict)
        row["class"] = verdict["class"]

        truth = open(f"{BUILD}/gostacks.txt").read()
        truth_ok = truth.index("main.c") < truth.index("main.b") < truth.index("main.a")
        ours_ok = (
            "main.c" in text and text.index("main.c") < text.index("main.b") < text.index("main.a")
        )
        chain_line = next((l for l in verdict["chain"] if "main.c" in l), "")
        row["headline"] = chain_line or verdict["headline"]
        row["passed"] = truth_ok and ours_ok and verdict["class"] == "PARTIAL"
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()


def run_pipes_row():
    """The blocks compose like pipes: snap | judge must reach the same
    verdict class offline, with the documented exit code."""
    row = {"name": "pipes", "expected": "PARTIAL", "passed": False}
    proc = subprocess.Popen(
        [sys.executable, "scenarios/slowdb.py"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
    )
    try:
        target = read_ready(proc)
        if target is None:
            row["error"] = "scenario never printed READY"
            return row
        time.sleep(0.8)
        t0 = time.monotonic()
        snap = subprocess.run([BIN, "snap", str(target)], capture_output=True, text=True, timeout=10)
        judged = subprocess.run(
            [BIN, "judge", "--json"], input=snap.stdout, capture_output=True, text=True, timeout=10
        )
        row["seconds"] = round(time.monotonic() - t0, 2)
        verdict = json.loads(judged.stdout)
        row["class"] = verdict["class"]
        row["headline"] = verdict["headline"]
        # Offline judging has no live socket hop, so the wire verdict here
        # is PARTIAL where the live one is CAUSAL; exit code must be 0.
        row["passed"] = (
            verdict["class"] == "PARTIAL" and "5432" in judged.stdout and judged.returncode == 0
        )
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()


def run_overhead_row():
    """Do-no-harm, measured: diagnosing a throughput-counting target must
    not dent its rate beyond three sigma of its own baseline noise."""
    row = {"name": "overhead", "expected": "DO-NO-HARM", "passed": False}
    proc = subprocess.Popen(
        [sys.executable, "scenarios/overhead.py"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True,
    )
    try:
        if read_ready(proc) is None:
            row["error"] = "scenario never printed READY"
            return row

        def rates(n):
            out = []
            while len(out) < n:
                line = proc.stdout.readline()
                if not line:
                    break
                try:
                    out.append(int(line))
                except ValueError:
                    pass
            return out

        rates(3)
        baseline = rates(12)
        t0 = time.monotonic()
        collected = []

        def diagnose():
            for _ in range(4):
                subprocess.run([BIN, str(proc.pid), "--json"], capture_output=True, timeout=10)

        d = threading.Thread(target=diagnose)
        d.start()
        while d.is_alive():
            collected.extend(rates(1))
        d.join()
        row["seconds"] = round(time.monotonic() - t0, 2)

        mean = lambda xs: sum(xs) / len(xs)
        base_m = mean(baseline)
        sigma = (mean([(x - base_m) ** 2 for x in baseline])) ** 0.5
        dur_m = mean(collected) if collected else 0
        delta_pct = (dur_m - base_m) / base_m * 100
        row["class"] = "measured"
        row["headline"] = (
            f"baseline {base_m:.0f} iters/100ms (sigma {sigma:.0f}), under diagnosis {dur_m:.0f} "
            f"({delta_pct:+.1f}%), gate: within 3 sigma over {len(collected)} windows x 4 diagnoses"
        )
        row["passed"] = bool(collected) and dur_m >= base_m - 3 * sigma
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()


def main():
    build_c()
    rows = [run_one(*s) for s in SCENARIOS]
    rows.append(run_scan_row())
    rows.append(run_watch_row())
    rows.append(run_pipes_row())
    rows.append(run_overhead_row())
    rows.append(run_gounwind_row())
    rows.extend(run_cooperate_rows())
    passed = sum(r["passed"] for r in rows)

    print(f"\n{'scenario':<11} {'verdict':<12} {'want':<12} {'time':>5}  result")
    for r in rows:
        got = r.get("class", "-")
        secs = f"{r.get('seconds', 0):.2f}s" if "seconds" in r else "-"
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"{r['name']:<11} {got:<12} {r['expected']:<12} {secs:>5}  {mark}")
        detail = r.get("headline") or r.get("error", "")
        print(f"            {detail}")

    total = len(rows)
    print(f"\nhangbook: {passed}/{total}")
    with open(os.path.join(ROOT, "results.json"), "w") as f:
        json.dump({"passed": passed, "total": total, "rows": rows}, f, indent=2)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()

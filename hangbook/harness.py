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
    ("gochan", [f"{BUILD}/gochan"], "PARTIAL", [["goroutine"], ["chan receive"]], None),
    ("gostripped", [f"{BUILD}/gostripped"], "REFUSAL", [["stripped"]], None),
    ("threadstuck", [sys.executable, "scenarios/threadstuck.py"], "CAUSAL", [["9009"], ["sleep"], ["most-blocked"]], None),
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
    proc = subprocess.Popen(
        cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True
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
        if out.returncode != 0:
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
    """Launch a D-state hang, a busy loop, and a healthy idle loop; scan
    must flag the first two and leave the healthy one alone."""
    row = {"name": "scan", "expected": "FINDINGS", "passed": False}
    procs = {}
    try:
        for name, cmd in [
            ("dstate", [f"{BUILD}/dstate"]),
            ("busyloop", [sys.executable, "scenarios/busyloop.py"]),
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
        spared_idle = procs["epollidle"][1] not in found
        row["class"] = f"flagged {len(found)}"
        row["headline"] = f"dstate {'flagged' if flagged_d else 'MISSED'}, busyloop {'flagged' if flagged_busy else 'MISSED'}, idle {'spared' if spared_idle else 'WRONGLY FLAGGED'}"
        row["passed"] = flagged_d and flagged_busy and spared_idle
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


def main():
    build_c()
    rows = [run_one(*s) for s in SCENARIOS]
    rows.append(run_scan_row())
    rows.append(run_watch_row())
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
